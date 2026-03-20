import struct
from .types import FiveTuple, classify_app, AppType
from .packet_parser import parse_packet
from .sni_extractor import SNIExtractor
from .connection_tracker import ConnectionTracker
from .rule_manager import RuleManager
import sys

# We'll support importing MLPredictor optionally
try:
    from ..ml.predictor import MLPredictor
except ImportError:
    MLPredictor = None

class PcapWriter:
    def __init__(self, filename: str):
        self.file = open(filename, 'wb')
        self.file.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def write_packet(self, data: bytes):
        header = struct.pack('<IIII', 0, 0, len(data), len(data))
        self.file.write(header)
        self.file.write(data)
        
    def close(self):
        self.file.close()

class DPIEngine:
    def __init__(self, use_ml=False, hybrid_mode=False, ml_conf=0.8):
        self.tracker = ConnectionTracker()
        self.rule_manager = RuleManager()
        self.use_ml = use_ml
        self.hybrid_mode = hybrid_mode
        self.ml_conf = ml_conf
        
        self.predictor = None
        if (use_ml or hybrid_mode) and MLPredictor:
            try:
                self.predictor = MLPredictor()
            except Exception as e:
                print(f"Warning: Failed to load ML Model: {e}")

    def process_packet_detailed(self, data: bytes, timestamp: float = 0.0):
        parsed = parse_packet(data, timestamp)
        if not parsed:
            return None, True, ""
            
        tuple_key = FiveTuple(
            src_ip=parsed.src_ip, dst_ip=parsed.dst_ip,
            src_port=parsed.src_port, dst_port=parsed.dst_port,
            protocol=parsed.protocol
        )
        flow = self.tracker.get_flow(tuple_key)
        
        # SNI parsing
        sni_found = False
        if not self.use_ml:
            if not flow.sni and parsed.payload:
                sni = SNIExtractor.extract_domain(parsed.payload, parsed.dst_port)
                if sni:
                    flow.sni = sni
                    flow.app_type = classify_app(sni, parsed.dst_port)
                    flow.predict_source = "SNI"
                    flow.ml_confidence = 1.0
                    sni_found = True

        # ML Prediction Hook (only predict if needed)
        # For performance, we only predict if we don't have SNI (Hybrid) or if ML only.
        if self.predictor and flow.packet_count >= 1: # Predict dynamically
            if self.use_ml or (self.hybrid_mode and not flow.sni):
                # We update the tracker's packet count manually before predict
                # so the ML model sees the new packet sizes.
                predicted_app, conf = self.predictor.predict(flow, parsed)
                if conf >= self.ml_conf:
                    flow.app_type = predicted_app
                    flow.predict_source = "ML"
                    flow.ml_confidence = conf

        drop = self.rule_manager.should_block(parsed, flow)
        reason = "Blocked by rule" if drop else ""
        
        self.tracker.update_flow(flow, parsed, drop)
        
        return parsed, not drop, reason

    def process_packet(self, data: bytes, timestamp: float = 0.0) -> bool:
        _, forward, _ = self.process_packet_detailed(data, timestamp)
        return forward
