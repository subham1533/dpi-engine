import numpy as np

def extract_features(flow) -> np.ndarray:
    """
    Extracts 16 flow-level features into a numpy array for ML prediction.
    Features: duration, packets, bytes, avg_size, std_size, min_size, max_size,
              bps, pps, syn_ct, ack_ct, fin_ct, dst_port, src_port, has_tls, entropy
    """
    duration = flow.end_time - flow.start_time
    if duration <= 0:
        duration = 0.0001
        
    packets = flow.packet_count
    bytes_ = flow.byte_count
    
    avg_size = bytes_ / packets if packets > 0 else 0
    var = (flow.sum_sq_packet_size / packets) - (avg_size ** 2) if packets > 0 else 0
    if var < 0: var = 0
    std_size = np.sqrt(var)
    
    min_size = flow.min_packet_size if flow.min_packet_size != -1 else 0
    max_size = flow.max_packet_size
    
    bps = bytes_ / duration
    pps = packets / duration
    
    syn_ct = flow.syn_count
    ack_ct = flow.ack_count
    fin_ct = flow.fin_count
    
    dst_port = flow.flow_id.dst_port
    src_port = flow.flow_id.src_port
    
    has_tls = flow.has_tls
    entropy_avg = np.mean(flow.payload_entropies) if flow.payload_entropies else 0.0
    
    return np.array([
        duration, packets, bytes_, avg_size, std_size, min_size, max_size,
        bps, pps, syn_ct, ack_ct, fin_ct, dst_port, src_port, has_tls, entropy_avg
    ]).reshape(1, 16)
