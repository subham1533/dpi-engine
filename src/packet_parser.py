import struct
from dataclasses import dataclass
from typing import Optional

@dataclass
class ParsedPacket:
    src_mac: str
    dst_mac: str
    ethertype: int
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int
    dst_port: int
    payload: bytes
    total_length: int
    
    # ML Features
    timestamp: float = 0.0
    syn_flag: bool = False
    ack_flag: bool = False
    fin_flag: bool = False

def parse_mac(mac_bytes: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def parse_ip(ip_bytes: bytes) -> str:
    return '.'.join(str(b) for b in ip_bytes)

def parse_packet(data: bytes, timestamp: float = 0.0) -> Optional[ParsedPacket]:
    if len(data) < 14:
        return None

    dst_mac = parse_mac(data[0:6])
    src_mac = parse_mac(data[6:12])
    ethertype = struct.unpack('>H', data[12:14])[0]

    if ethertype != 0x0800:
        return None

    if len(data) < 34:
        return None

    version_ihl = data[14]
    ihl = (version_ihl & 0x0F) * 4
    
    protocol = data[23]
    src_ip = parse_ip(data[26:30])
    dst_ip = parse_ip(data[30:34])

    transport_offset = 14 + ihl

    src_port = 0
    dst_port = 0
    payload = b''
    syn_flag = ack_flag = fin_flag = False

    if protocol == 6:  # TCP
        if len(data) < transport_offset + 20:
            return None
        
        src_port, dst_port = struct.unpack('>HH', data[transport_offset:transport_offset+4])
        data_offset_and_flags = struct.unpack('>H', data[transport_offset+12:transport_offset+14])[0]
        
        flags = data_offset_and_flags & 0x01FF
        fin_flag = bool(flags & 0x01)
        syn_flag = bool(flags & 0x02)
        ack_flag = bool(flags & 0x10)
        
        data_offset = (data_offset_and_flags >> 12) * 4
        payload_offset = transport_offset + data_offset
        if payload_offset <= len(data):
            payload = data[payload_offset:]
            
    elif protocol == 17:  # UDP
        if len(data) < transport_offset + 8:
            return None
            
        src_port, dst_port = struct.unpack('>HH', data[transport_offset:transport_offset+4])
        payload_offset = transport_offset + 8
        if payload_offset <= len(data):
            payload = data[payload_offset:]
    else:
        return None

    return ParsedPacket(
        src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype,
        src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
        src_port=src_port, dst_port=dst_port, payload=payload,
        total_length=len(data), timestamp=timestamp,
        syn_flag=syn_flag, ack_flag=ack_flag, fin_flag=fin_flag
    )
