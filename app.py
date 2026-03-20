import argparse
import sys
import re
from collections import defaultdict
from colorama import init, Fore, Style
from src.types import AppType
from src.rule_manager import RuleManager
from src.connection_tracker import ConnectionTracker
from src.dpi_engine import DPIEngine
from src.main_simple import run_simple
from src.dpi_mt import run_mt

init(autoreset=True)

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def print_and_log(msg, log_file):
    print(msg)
    if log_file:
        log_file.write(strip_ansi(msg) + "\n")

def print_report(stats_dict, engine, args, is_mt, log_file):
    print_and_log("\n╔══════════════════════════════════════════════════════════════╗", log_file)
    print_and_log("║                      PROCESSING REPORT                        ║", log_file)
    print_and_log("╠══════════════════════════════════════════════════════════════╣", log_file)
    
    if is_mt:
        total_pkts = stats_dict['total_packets']
        total_fwd = sum(d['forwarded'] for d in stats_dict['fp_stats'].values())
        total_drp = sum(d['dropped'] for d in stats_dict['fp_stats'].values())
    else:
        total_pkts = stats_dict['total_packets']
        total_fwd = stats_dict['forwarded']
        total_drp = stats_dict['dropped']
        
    fwd_c = f"{Fore.GREEN}{total_fwd:<31}{Style.RESET_ALL}"
    drp_c = f"{Fore.RED}{total_drp:<30}{Style.RESET_ALL}"
    
    print_and_log(f"║ Total Packets:                {total_pkts:<31} ║", log_file)
    print(f"║ Forwarded:                    {fwd_c} ║")
    if log_file: log_file.write(f"║ Forwarded:                    {total_fwd:<31} ║\n")
    print(f"║ Dropped:                       {drp_c} ║")
    if log_file: log_file.write(f"║ Dropped:                       {total_drp:<30} ║\n")
    
    if is_mt:
        print_and_log("╠══════════════════════════════════════════════════════════════╣", log_file)
        print_and_log("║ THREAD STATISTICS                                             ║", log_file)
        lbs = sorted(stats_dict['lb_stats'].items())
        fps = sorted(stats_dict['fp_stats'].items())
        max_len = max(len(lbs), len(fps))
        for i in range(max_len):
            lb_str = f"LB{i} dispatched: {lbs[i][1]}" if i < len(lbs) else ""
            fp_str = f"FP{i} processed: {fps[i][1]['processed']}" if i < len(fps) else ""
            print_and_log(f"║   {lb_str:<20} {fp_str:<20}               ║", log_file)

    print_and_log("╠══════════════════════════════════════════════════════════════╣", log_file)
    print_and_log("║                   APPLICATION BREAKDOWN                       ║", log_file)
    print_and_log("╠══════════════════════════════════════════════════════════════╣", log_file)

    app_counts = defaultdict(int)
    detected_snis = {}
    total_app_flows = 0
    tracker = engine.tracker if not is_mt else engine
    
    for f in tracker.flows.values():
        total_app_flows += 1
        app_counts[f.app_type] += 1
        if f.sni:
            detected_snis[f.sni] = f.app_type
            
    sorted_types = sorted(app_counts.items(), key=lambda x: (x[0] == AppType.UNKNOWN, -x[1]))
    
    for app_type, count in sorted_types:
        pct = (count / total_app_flows * 100) if total_app_flows > 0 else 0
        flows_of_type = [f for f in tracker.flows.values() if f.app_type == app_type]
        any_blocked = any(f.is_blocked for f in flows_of_type)
        
        sources = [f.predict_source for f in flows_of_type if f.predict_source]
        confs = [f.ml_confidence for f in flows_of_type if f.predict_source]
        avg_conf = sum(confs)/len(confs) if confs else 0.0
        dominant_src = max(set(sources), key=sources.count) if sources else ""
        
        conf_str = ""
        if pd := dominant_src:
            if pd == "SNI":
                conf_str = "[SNI: 100%]"
            else:
                conf_pct = avg_conf * 100
                suffix = " - low confidence" if conf_pct < 70 else " confidence"
                conf_str = f"[ML: {conf_pct:.1f}%{suffix}]"
                
        # Build text string
        tags = []
        if any_blocked: tags.append("(BLOCKED)")
        if conf_str: tags.append(conf_str)
        
        t_clean = f" # {' '.join(tags)}" if tags else ""
        
        c_tags = []
        if any_blocked: c_tags.append(f"{Fore.RED}(BLOCKED){Style.RESET_ALL}")
        if conf_str: c_tags.append(f"{Fore.CYAN}{conf_str}{Style.RESET_ALL}")
        t_color = f" # {' '.join(c_tags)}" if c_tags else ""
        
        row_clean = f"{app_type.value:<10} {count:<3} {pct:>4.1f}%{t_clean}"
        row_color = f"{app_type.value:<10} {count:<3} {pct:>4.1f}%{t_color}"
        
        print(f"║ {row_color:<80} ║") 
        if log_file: log_file.write(f"║ {row_clean:<60} ║\n")
        
    print_and_log("╚══════════════════════════════════════════════════════════════╝", log_file)
    
    print_and_log("\n[Detected Domains/SNIs]", log_file)
    for sni, app in detected_snis.items():
        print_and_log(f"  - {sni} -> {app.value}", log_file)

def main():
    parser = argparse.ArgumentParser(description="DPI Engine v2.0")
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('output', nargs='?', default='output.pcap', help='Output PCAP file')
    parser.add_argument('--block-app', action='append', default=[], help='Block specific applications')
    parser.add_argument('--block-ip', action='append', default=[], help='Block specific IP')
    parser.add_argument('--block-domain', action='append', default=[], help='Block specific domain keywords')
    parser.add_argument('--lbs', type=int, default=2, help='Number of load balancer threads')
    parser.add_argument('--fps', type=int, default=2, help='Number of fast path threads per LB')
    parser.add_argument('--verbose', action='store_true', help='Show each packet decision')
    parser.add_argument('--stats-only', action='store_true', help='Skip writing output.pcap')
    
    # ML Args
    parser.add_argument('--ml-mode', action='store_true', help='Use ML classifier only')
    parser.add_argument('--hybrid-mode', action='store_true', help='Use both SNI + ML (default)')
    parser.add_argument('--confidence', type=float, default=0.8, help='Minimum ML confidence threshold')
    
    args = parser.parse_args()

    # Determine execution configs
    use_ml = args.ml_mode
    hybrid_mode = args.hybrid_mode or not args.ml_mode
    ml_conf = args.confidence

    log_file = open("report.txt", "w", encoding='utf-8')
    
    try:
        print_and_log("╔══════════════════════════════════════════════════════════════╗", log_file)
        if args.lbs > 0 and args.fps > 0:
            print_and_log("║              DPI ENGINE v2.0 (Multi-threaded)                 ║", log_file)
        else:
            print_and_log("║              DPI ENGINE v2.0 (Single-threaded)                ║", log_file)
        print_and_log("╠══════════════════════════════════════════════════════════════╣", log_file)
        
        if args.lbs > 0 and args.fps > 0:
            total_fps = args.lbs * args.fps
            print_and_log(f"║ Load Balancers: {args.lbs:>2}    FPs per LB: {args.fps:>2}    Total FPs: {total_fps:>2}        ║", log_file)
            print_and_log("╚══════════════════════════════════════════════════════════════╝\n", log_file)
        else:
            print_and_log("║                                                              ║", log_file)
            print_and_log("╚══════════════════════════════════════════════════════════════╝\n", log_file)

        tracker = ConnectionTracker()
        rule_manager = RuleManager()

        for app_str in args.block_app:
            try:
                for at in AppType:
                    if at.value.lower() == app_str.lower():
                        rule_manager.block_app(at)
                        print_and_log(f"[{Fore.YELLOW}Rules{Style.RESET_ALL}] Blocked app: {at.value}", log_file)
                        break
            except ValueError:
                print_and_log(f"Warning: Unknown app {app_str}", log_file)

        for ip in args.block_ip:
            rule_manager.block_ip(ip)
            print_and_log(f"[{Fore.YELLOW}Rules{Style.RESET_ALL}] Blocked IP: {ip}", log_file)
            
        for dom in args.block_domain:
            rule_manager.block_domain(dom)
            print_and_log(f"[{Fore.YELLOW}Rules{Style.RESET_ALL}] Blocked Domain: {dom}", log_file)
            
        print_and_log("", log_file)

        if args.lbs > 0 and args.fps > 0:
            stats = run_mt(args.input, args.output, args.lbs, args.fps, tracker, rule_manager, args.verbose, args.stats_only, use_ml, hybrid_mode, ml_conf)
            print_report(stats, tracker, args, True, log_file)
        else:
            engine = DPIEngine(use_ml=use_ml, hybrid_mode=hybrid_mode, ml_conf=ml_conf)
            engine.tracker = tracker
            engine.rule_manager = rule_manager
            stats = run_simple(args.input, args.output, engine, args.verbose, args.stats_only)
            print_report(stats, tracker, args, False, log_file)
            
    except FileNotFoundError as e:
        print_and_log(f"\n[{Fore.RED}Error{Style.RESET_ALL}] Could not open file: {e}", log_file)
        sys.exit(1)
    except Exception as e:
        print_and_log(f"\n[{Fore.RED}Error{Style.RESET_ALL}] An unexpected error occurred: {e}", log_file)
        sys.exit(1)
    finally:
        log_file.close()

if __name__ == '__main__':
    main()
