from .pcap_reader import PcapReader
from .dpi_engine import DPIEngine, PcapWriter
from tqdm import tqdm
from colorama import Fore, Style

def run_simple(input_pcap: str, output_pcap: str, engine: DPIEngine, verbose: bool, stats_only: bool) -> dict:
    total_packets = 0
    forwarded = 0
    dropped = 0
    
    print(f"[{Fore.CYAN}Reader{Style.RESET_ALL}] Processing packets...")
    writer = PcapWriter(output_pcap) if not stats_only else None
    
    try:
        with PcapReader(input_pcap) as reader:
            for timestamp, packet_data in tqdm(reader.read_packets(), desc="Processing", unit="pkt", smoothing=0.1):
                total_packets += 1
                
                parsed, forward, reason = engine.process_packet_detailed(packet_data, timestamp)
                
                if verbose and parsed:
                    status_c = f"{Fore.GREEN}FORWARDED{Style.RESET_ALL}" if forward else f"{Fore.RED}DROPPED ({reason}){Style.RESET_ALL}"
                    tqdm.write(f"[{parsed.protocol}] {parsed.src_ip}:{parsed.src_port} -> {parsed.dst_ip}:{parsed.dst_port} : {status_c}")
                
                if forward:
                    forwarded += 1
                    if writer:
                        writer.write_packet(packet_data)
                else:
                    dropped += 1
    finally:
        if writer:
            writer.close()
            
    print(f"[{Fore.CYAN}Reader{Style.RESET_ALL}] Done reading {total_packets} packets")
    
    return {
        "total_packets": total_packets,
        "forwarded": forwarded,
        "dropped": dropped
    }
