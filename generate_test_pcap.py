import argparse
from scapy.all import IP, TCP, UDP, Ether, wrpcap, Raw

def generate_pcap(filename):
    packets = []
    
    # Flow 1: HTTP Traffic (Port 80)
    p1 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
         IP(src="192.168.1.10", dst="10.0.0.5") / \
         TCP(sport=12345, dport=80, flags="A") / \
         Raw(load="GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
    packets.append(p1)
    
    # Flow 2: YouTube TLS Traffic (Port 443) -> Should be blocked if --block-app YouTube
    # Simulating a TLS Client Hello with SNI "www.youtube.com"
    # To properly simulate TLS, we need the binary structure
    # Record Header (5): 16 03 01 00 3c
    # Handshake Header (4): 01 00 00 38
    # Client Hello content (version, random, session, ciphers, comp, extensions)
    # This is a minimal mock just for testing our parser
    
    # Let's craft a raw payload that matches our parser's expectations
    # 16 (ContentType) | 03 01 (Version) | 00 3c (Length)
    # 01 (HandshakeType) | 00 00 38 (Length)
    # 03 01 (Version) | 32 bytes Random ...
    tls_payload = bytearray.fromhex(
        "160301004a" + 
        "01000046" +
        "0303" +
        ("00"*32) + # random
        "00" + # session id len
        "00020000" + # cipher suites (2 bytes len + 2 bytes)
        "0100" + # comp methods (1 byte len + 1 byte)
        "0019" + # extensions len (25 bytes)
        "00000015001300000f7777772e796f75747562652e636f6d" # SNI extension for www.youtube.com
    )
    
    p2_yt = Ether() / IP(src="192.168.1.5", dst="142.250.190.46") / TCP(sport=54321, dport=443) / Raw(load=bytes(tls_payload))
    # We will duplicate this packet 4 times to match the example output 
    for _ in range(4):
        packets.append(p2_yt)

    # Flow 3: Dummy DNS Traffic (Port 53)
    p3 = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=33333, dport=53) / Raw(load="dummy_dns")
    packets.append(p3)

    # Some extra padding to reach ~77 packets like in the example
    for _ in range(71):
         p_dummy = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=2000) / Raw(load="padding")
         packets.append(p_dummy)

    wrpcap(filename, packets)
    print(f"Generated {len(packets)} packets in {filename}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default='test_dpi.pcap')
    args = parser.parse_args()
    generate_pcap(args.output)
