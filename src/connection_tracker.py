import math
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from .types import FiveTuple, AppType

def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

@dataclass
class FlowContext:
    flow_id: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: Optional[str] = None
    is_blocked: bool = False
    
    packet_count: int = 0
    byte_count: int = 0
    
    # ML Features
    start_time: float = 0.0
    end_time: float = 0.0
    min_packet_size: int = -1
    max_packet_size: int = 0
    sum_packet_size: int = 0
    sum_sq_packet_size: int = 0
    
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    
    has_tls: int = 0
    payload_entropies: List[float] = field(default_factory=list)
    
    predict_source: str = ""
    ml_confidence: float = 0.0

class ConnectionTracker:
    def __init__(self):
        self.flows: Dict[FiveTuple, FlowContext] = {}

    @staticmethod
    def normalize_tuple(f: FiveTuple) -> FiveTuple:
        if f.src_ip < f.dst_ip or (f.src_ip == f.dst_ip and f.src_port < f.dst_port):
            return f
        return FiveTuple(f.dst_ip, f.src_ip, f.dst_port, f.src_port, f.protocol)

    def get_flow(self, tuple_key: FiveTuple) -> FlowContext:
        norm = self.normalize_tuple(tuple_key)
        if norm not in self.flows:
            self.flows[norm] = FlowContext(flow_id=norm)
        return self.flows[norm]

    def update_flow(self, flow: FlowContext, parsed, drop: bool):
        flow.packet_count += 1
        flow.byte_count += parsed.total_length
        flow.sum_packet_size += parsed.total_length
        flow.sum_sq_packet_size += parsed.total_length ** 2
        
        if flow.min_packet_size == -1 or parsed.total_length < flow.min_packet_size:
            flow.min_packet_size = parsed.total_length
        if parsed.total_length > flow.max_packet_size:
            flow.max_packet_size = parsed.total_length
            
        if flow.start_time == 0.0:
            flow.start_time = parsed.timestamp
        flow.end_time = parsed.timestamp
        
        if parsed.syn_flag: flow.syn_count += 1
        if parsed.ack_flag: flow.ack_count += 1
        if parsed.fin_flag: flow.fin_count += 1
        
        if parsed.payload:
            ent = calculate_entropy(parsed.payload)
            flow.payload_entropies.append(ent)
            if parsed.dst_port == 443 and parsed.payload[0] == 0x16:
                flow.has_tls = 1
                
        if drop:
            flow.is_blocked = True
