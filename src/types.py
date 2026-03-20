import enum
from dataclasses import dataclass

class AppType(enum.Enum):
    YOUTUBE = "YouTube"
    FACEBOOK = "Facebook"
    TIKTOK = "TikTok"
    GOOGLE = "Google"
    GITHUB = "GitHub"
    NETFLIX = "Netflix"
    INSTAGRAM = "Instagram"
    TWITTER = "Twitter"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    GAMING = "Gaming"
    ZOOM = "Zoom/Meet"
    UNKNOWN = "Unknown"

@dataclass
class FiveTuple:
    """
    Represents the 5-tuple of a network packet flow.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and 
                self.dst_ip == other.dst_ip and 
                self.src_port == other.src_port and 
                self.dst_port == other.dst_port and 
                self.protocol == other.protocol)

def classify_app(sni: str, port: int = 0) -> AppType:
    """
    Classifies the application type based on SNI and destination port.
    """
    if sni:
        sni_lower = sni.lower()
        if "youtube" in sni_lower:
            return AppType.YOUTUBE
        elif "facebook" in sni_lower:
            return AppType.FACEBOOK
        elif "tiktok" in sni_lower:
            return AppType.TIKTOK
        elif "google" in sni_lower:
            return AppType.GOOGLE
        elif "github" in sni_lower:
            return AppType.GITHUB
        elif "netflix" in sni_lower:
            return AppType.NETFLIX
        elif "instagram" in sni_lower:
            return AppType.INSTAGRAM
        elif "twitter" in sni_lower:
            return AppType.TWITTER

    # Fallback to port-based classification
    if port == 53:
        return AppType.DNS
    elif port == 80:
        return AppType.HTTP
    elif port == 443:
        return AppType.HTTPS
        
    return AppType.UNKNOWN
