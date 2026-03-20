import threading
import queue
from typing import List, Dict
from tqdm import tqdm
from colorama import Fore, Style

from .pcap_reader import PcapReader
from .packet_parser import parse_packet
from .types import FiveTuple, classify_app, AppType
from .sni_extractor import SNIExtractor
from .rule_manager import RuleManager
from .connection_tracker import ConnectionTracker
from .dpi_engine import PcapWriter
import sys

# Optional Predictor for ML features in MT FastPath
try:
    from ..ml.predictor import MLPredictor
except ImportError:
    MLPredictor = None

class LoadBalancerThread(threading.Thread):
    def __init__(self, thread_id: int, input_queue: queue.Queue, fp_queues: List[queue.Queue]):
        super().__init__()
        self.thread_id = thread_id
        self.input_queue = input_queue
        self.fp_queues = fp_queues
        self.dispatched = 0
        
    def run(self):
        while True:
            item = self.input_queue.get()
            if item is None:
                for q in self.fp_queues:
                    q.put(None)
                break
                
            timestamp, packet_data = item
            parsed = parse_packet(packet_data, timestamp)
            if not parsed:
                self.fp_queues[0].put((timestamp, packet_data, parsed))
            else:
                tuple_key = FiveTuple(
                    src_ip=parsed.src_ip, dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port, dst_port=parsed.dst_port,
                    protocol=parsed.protocol
                )
                fp_index = hash(tuple_key) % len(self.fp_queues)
                self.fp_queues[fp_index].put((timestamp, packet_data, parsed))
                
            self.dispatched += 1

class FastPathThread(threading.Thread):
    def __init__(self, thread_id: int, input_queue: queue.Queue, 
                 tracker: ConnectionTracker, rule_manager: RuleManager, 
                 stats_dict: dict, write_lock: threading.Lock, writer: PcapWriter,
                 verbose: bool, use_ml: bool, hybrid_mode: bool, ml_conf: float):
        super().__init__()
        self.thread_id = thread_id
        self.input_queue = input_queue
        self.tracker = tracker
        self.rule_manager = rule_manager
        self.stats = stats_dict
        self.processed = 0
        self.forwarded = 0
        self.dropped = 0
        self.write_lock = write_lock
        self.writer = writer
        self.verbose = verbose
        self.use_ml = use_ml
        self.hybrid_mode = hybrid_mode
        self.ml_conf = ml_conf
        self.active_lb_count = 0
        
        self.predictor = None
        if (use_ml or hybrid_mode) and MLPredictor:
            try:
                self.predictor = MLPredictor()
            except:
                pass

    def run(self):
        while True:
            item = self.input_queue.get()
            if item is None:
                self.active_lb_count -= 1
                if self.active_lb_count <= 0:
                    break
                continue
                
            timestamp, packet_data, parsed = item
            forward = True
            drop_reason = ""
            
            if parsed:
                tuple_key = FiveTuple(
                    src_ip=parsed.src_ip, dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port, dst_port=parsed.dst_port,
                    protocol=parsed.protocol
                )
                
                with threading.Lock():
                    flow = self.tracker.get_flow(tuple_key)
                    if not self.use_ml:
                        if not flow.sni and parsed.payload:
                            sni = SNIExtractor.extract_domain(parsed.payload, parsed.dst_port)
                            if sni:
                                flow.sni = sni
                                flow.app_type = classify_app(sni, parsed.dst_port)
                                flow.predict_source = "SNI"
                                flow.ml_confidence = 1.0
                            
                    if self.predictor and flow.packet_count >= 1:
                        if self.use_ml or (self.hybrid_mode and not flow.sni):
                            predicted_app, conf = self.predictor.predict(flow, parsed)
                            if conf >= self.ml_conf:
                                flow.app_type = predicted_app
                                flow.predict_source = "ML"
                                flow.ml_confidence = conf

                    drop = self.rule_manager.should_block(parsed, flow)
                    if drop: drop_reason = "Blocked by rule"
                    self.tracker.update_flow(flow, parsed, drop)
                    forward = not drop
                    
            if self.verbose and parsed:
                st = f"{Fore.GREEN}FORWARDED{Style.RESET_ALL}" if forward else f"{Fore.RED}DROPPED ({drop_reason}){Style.RESET_ALL}"
                msg = f"[FP{self.thread_id}] [{parsed.protocol}] {parsed.src_ip}:{parsed.src_port} -> {parsed.dst_ip}:{parsed.dst_port} : {st}"
                tqdm.write(msg)
            
            if forward:
                self.forwarded += 1
                if self.writer:
                    with self.write_lock:
                        self.writer.write_packet(packet_data)
            else:
                self.dropped += 1
                
            self.processed += 1
        
        self.stats[f'fp_{self.thread_id}'] = {
            'processed': self.processed,
            'forwarded': self.forwarded,
            'dropped': self.dropped
        }

def run_mt(input_pcap: str, output_pcap: str, num_lbs: int, num_fps_per_lb: int,
           tracker: ConnectionTracker, rule_manager: RuleManager, verbose: bool, stats_only: bool,
           use_ml: bool=False, hybrid_mode: bool=False, ml_conf: float=0.8) -> dict:
    
    total_fps = num_lbs * num_fps_per_lb
    lb_queues = [queue.Queue() for _ in range(num_lbs)]
    fp_queues = [queue.Queue() for _ in range(total_fps)]
    
    writer = PcapWriter(output_pcap) if not stats_only else None
    write_lock = threading.Lock()
    stats_dict = {}
    
    lbs = []
    for i in range(num_lbs):
        start_fp = i * num_fps_per_lb
        end_fp = start_fp + num_fps_per_lb
        lb = LoadBalancerThread(i, lb_queues[i], fp_queues[start_fp:end_fp])
        lbs.append(lb)

    fps = []
    for i in range(total_fps):
        fp = FastPathThread(i, fp_queues[i], tracker, rule_manager, stats_dict, write_lock, writer, verbose, use_ml, hybrid_mode, ml_conf)
        fp.active_lb_count = 1  
        fps.append(fp)
        
    for fp in fps: fp.start()
    for lb in lbs: lb.start()
        
    print(f"[{Fore.CYAN}Reader{Style.RESET_ALL}] Processing packets...")
    total_packets = 0
    try:
        with PcapReader(input_pcap) as reader:
            for timestamp, packet_data in tqdm(reader.read_packets(), desc="Dispatching", unit="pkt", smoothing=0.1):
                lb_idx = total_packets % num_lbs
                lb_queues[lb_idx].put((timestamp, packet_data))
                total_packets += 1
    finally:
        for q in lb_queues:
            q.put(None)
            
    for lb in lbs: lb.join()
    for fp in fps: fp.join()
        
    if writer: writer.close()
    print(f"[{Fore.CYAN}Reader{Style.RESET_ALL}] Done reading {total_packets} packets")
    
    lb_stats = {f'lb_{lb.thread_id}': lb.dispatched for lb in lbs}
    return {
        "total_packets": total_packets,
        "lb_stats": lb_stats,
        "fp_stats": stats_dict
    }
