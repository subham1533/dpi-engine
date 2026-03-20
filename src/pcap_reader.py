import struct

class PcapReader:
    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, 'rb')
        global_header = self.file.read(24)
        if len(global_header) < 24:
            raise ValueError(f"Invalid PCAP file: {filename}")
        self.magic_number = struct.unpack('<I', global_header[:4])[0]
        self.is_little_endian = True
        if self.magic_number in [0xa1b2c3d4, 0xa1b23c4d]:
            self.endian = '<'
        elif self.magic_number in [0xd4c3b2a1, 0x4d3cb2a1]:
            self.endian = '>'
            self.is_little_endian = False
        else:
            raise ValueError(f"Unknown PCAP magic number: {hex(self.magic_number)}")

    def read_packets(self):
        while True:
            header_bytes = self.file.read(16)
            if len(header_bytes) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{self.endian}IIII', header_bytes)
            packet_data = self.file.read(incl_len)
            if len(packet_data) < incl_len:
                break
            
            timestamp = ts_sec + (ts_usec / 1e6)
            yield timestamp, packet_data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
