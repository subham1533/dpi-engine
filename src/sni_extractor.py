import struct
import re
from typing import Optional

class SNIExtractor:
    @staticmethod
    def extract_domain(payload: bytes, dst_port: int) -> Optional[str]:
        """
        Attempts to extract the SNI from a TLS Client Hello payload,
        or the Host header from an HTTP payload.
        """
        if not payload:
            return None
        
        # Check HTTP
        if dst_port == 80:
            try:
                # Basic HTTP Host header extraction
                text = payload.decode('utf-8', errors='ignore')
                match = re.search(r'Host:\s*([^\r\n]+)', text, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            except Exception:
                pass
            return None
            
        # Check TLS Handshake (0x16)
        if dst_port == 443 and len(payload) > 43:
            if payload[0] == 0x16:  # Content Type: Handshake
                try:
                    # TLS Record Header: Type(1), Version(2), Length(2)
                    record_length = struct.unpack('>H', payload[3:5])[0]
                    
                    # Ensure we have enough data for the record
                    if len(payload) < 5 + record_length:
                        pass # proceed with what we have
                    
                    # Handshake Header: Type(1), Length(3)
                    if payload[5] == 0x01:  # Handshake Type: Client Hello
                        # Handshake payload length
                        hs_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
                        
                        # Client Hello structure
                        # Version (2), Random (32)
                        offset = 5 + 4 + 2 + 32
                        
                        # Session ID Length (1) + Session ID
                        session_id_length = payload[offset]
                        offset += 1 + session_id_length
                        
                        # Cipher Suites Length (2) + Cipher Suites
                        cipher_suites_length = struct.unpack('>H', payload[offset:offset+2])[0]
                        offset += 2 + cipher_suites_length
                        
                        # Compression Methods Length (1) + Compression Methods
                        compression_methods_length = payload[offset]
                        offset += 1 + compression_methods_length
                        
                        # Extensions Length (2)
                        extensions_length = struct.unpack('>H', payload[offset:offset+2])[0]
                        offset += 2
                        
                        end_offset = min(offset + extensions_length, len(payload))
                        
                        # Loop through extensions
                        while offset < end_offset:
                            ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
                            ext_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
                            offset += 4
                            
                            if ext_type == 0x0000:  # Server Name Indication
                                # SNI List Length (2)
                                sni_list_len = struct.unpack('>H', payload[offset:offset+2])[0]
                                sni_offset = offset + 2
                                
                                # Server Name Type (1)
                                name_type = payload[sni_offset]
                                sni_offset += 1
                                
                                # Server Name Length (2)
                                name_len = struct.unpack('>H', payload[sni_offset:sni_offset+2])[0]
                                sni_offset += 2
                                
                                if name_type == 0x00:  # hostname
                                    sni = payload[sni_offset:sni_offset+name_len].decode('utf-8', errors='ignore')
                                    return sni
                            offset += ext_len
                            
                except Exception:
                    # Catch index errors or unpack errors safely without crashing the fast path
                    pass
        return None
