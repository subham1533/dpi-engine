from typing import Set, List
from .types import AppType
from .connection_tracker import FlowContext
from .packet_parser import ParsedPacket

class RuleManager:
    """
    Manages blocking rules across IP, AppType, and Domain categories.
    """
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []

    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)

    def block_app(self, app: AppType):
        self.blocked_apps.add(app)

    def block_domain(self, keyword: str):
        self.blocked_domains.append(keyword.lower())

    def should_block(self, packet: ParsedPacket, flow: FlowContext) -> bool:
        """
        Determines if a packet should be dropped based on the flow context
        or the packet's source/destination IPs.
        """
        # Rule 1: IP Blocking
        if packet.src_ip in self.blocked_ips or packet.dst_ip in self.blocked_ips:
            return True

        # Rule 2: App Blocking
        if flow.app_type in self.blocked_apps:
            return True

        # Rule 3: Domain / Keyword Blocking
        if flow.sni:
            sni_lower = flow.sni.lower()
            for keyword in self.blocked_domains:
                if keyword in sni_lower:
                    return True

        # Flow was already marked as blocked previously
        if flow.is_blocked:
            return True

        return False
