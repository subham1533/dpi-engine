import sys
import os
import time
import argparse
import threading
from flask import Flask, render_template
from flask_socketio import SocketIO

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.types import AppType
from src.rule_manager import RuleManager
from src.connection_tracker import ConnectionTracker
from src.dpi_engine import DPIEngine
from src.pcap_reader import PcapReader

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dpi_secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

stats_lock = threading.Lock()
current_stats = {
    "total_packets": 0,
    "forwarded": 0,
    "dropped": 0,
    "bytes": 0,
    "speed": 0,
    "alerts": [],
    "snis": [],
    "app_breakdown": {}
}

def process_pcap(args):
    global current_stats

    use_ml = args.ml_mode
    hybrid_mode = args.hybrid_mode or not args.ml_mode
    
    tracker = ConnectionTracker()
    rule_manager = RuleManager()
    
    for app_str in args.block_app:
        try:
            for at in AppType:
                if at.value.lower() == app_str.lower():
                    rule_manager.block_app(at)
                    break
        except: pass
                
    for ip in args.block_ip: rule_manager.block_ip(ip)
    for dom in args.block_domain: rule_manager.block_domain(dom)

    engine = DPIEngine(use_ml=use_ml, hybrid_mode=hybrid_mode, ml_conf=args.confidence)
    engine.tracker = tracker
    engine.rule_manager = rule_manager

    start_time = time.time()
    last_emit = start_time
    
    # Wait briefly so dashboard can connect before stream starts
    time.sleep(2)
    print("Beginning background packet stream...")
    
    try:
        while True:
            with PcapReader(args.input) as reader:
                for timestamp, packet_data in reader.read_packets():
                    parsed, forward, reason = engine.process_packet_detailed(packet_data, timestamp)
                    
                    with stats_lock:
                        current_stats["total_packets"] += 1
                        current_stats["bytes"] += len(packet_data)
                        if forward:
                            current_stats["forwarded"] += 1
                        else:
                            current_stats["dropped"] += 1
                            if parsed:
                                alert = f"Blocked {parsed.protocol} {parsed.src_ip} -> {parsed.dst_ip} ({reason})"
                                if alert not in current_stats["alerts"]:
                                    current_stats["alerts"].append(alert)
                                    if len(current_stats["alerts"]) > 10:
                                        current_stats["alerts"].pop(0)
                            
                    now = time.time()
                    if now - last_emit >= 0.1:
                        with stats_lock:
                            elapsed = now - start_time
                            current_stats["speed"] = int(current_stats["total_packets"] / elapsed) if elapsed > 0 else 0
                            
                            app_breakdown = {}
                            snis = []
                            
                            for f in tracker.flows.values():
                                app_val = f.app_type.value
                                if app_val not in app_breakdown:
                                    app_breakdown[app_val] = 0
                                app_breakdown[app_val] += f.packet_count
                                
                                if f.sni:
                                    snis.append({
                                        "sni": f.sni,
                                        "app": app_val,
                                        "conf": f.ml_confidence
                                    })
                                    
                            current_stats["app_breakdown"] = app_breakdown
                            
                            unique_snis = []
                            seen_snis = set()
                            for s in snis:
                                if s["sni"] not in seen_snis:
                                    seen_snis.add(s["sni"])
                                    unique_snis.append(s)
                                    
                            current_stats["snis"] = unique_snis[-10:]
                            
                        socketio.emit('stats_update', current_stats)
                        last_emit = now
                        
                    # To simulate live traffic visualization tracking
                    time.sleep(0.05)
            # Re-read endlessly to simulate infinite live traffic
            time.sleep(1)

    except Exception as e:
        print(f"Error processing PCAP: {e}")
        
    finally:
        socketio.emit('stats_update', current_stats)
        print("Processing complete.")

@app.route('/')
def index():
    return render_template('index.html')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('--block-app', action='append', default=[], help='Block specific applications')
    parser.add_argument('--block-ip', action='append', default=[], help='Block specific IP')
    parser.add_argument('--block-domain', action='append', default=[], help='Block specific domain keywords')
    parser.add_argument('--ml-mode', action='store_true')
    parser.add_argument('--hybrid-mode', action='store_true', default=True)
    parser.add_argument('--confidence', type=float, default=0.8)
    
    args = parser.parse_args()
    
    t = threading.Thread(target=process_pcap, args=(args,))
    t.daemon = True
    t.start()
    
    print("Starting DPI Engine Live Dashboard on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    main()
