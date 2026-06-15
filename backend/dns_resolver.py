import socket
import threading
from backend.logger import get_system_logger

logger = get_system_logger('DNSResolver')


class DNSResolver:
    """
    Thread-safe DNS Resolver that performs reverse DNS lookups asynchronously
    and caches results to prevent UI and capture blocking.
    """
    def __init__(self):
        # Predefined mapping of known IPs to friendly names for demos/reporting
        self.cache = {
            '127.0.0.1': 'localhost',
            '::1': 'localhost',
            '8.8.8.8': 'dns.google',
            '8.8.4.4': 'dns.google',
            '1.1.1.1': 'cloudflare-dns',
            '1.0.0.1': 'cloudflare-dns',
            '192.168.1.1': 'Router/Gateway',
            # Simulated attack sources/targets
            '45.33.32.156': 'Attacker (Port Scan)',
            '185.220.101.34': 'Tor Exit Node (Attacker)',
            '89.248.167.131': 'Scanner (ShadowServer)',
            '94.102.49.190': 'Attacker (Brute Force)',
            '171.25.193.78': 'Suspicious Host',
            '198.96.155.3': 'Botnet Node (DDoS)'
        }
        self.lock = threading.Lock()
        self.resolving = set()

        # Get local IP and hostname
        try:
            hostname = socket.gethostname()
            self.cache[socket.gethostbyname(hostname)] = f'Local PC ({hostname})'
        except Exception:
            pass

    def get_display_name(self, ip):
        """
        Get display name for an IP address. Format: Name (IP) or just IP.
        Asynchronously resolves hostnames for uncached IPs in background.
        """
        if not ip or ip == 'AI_ENGINE' or ip == 'NETWORK':
            return ip
        
        with self.lock:
            if ip in self.cache:
                name = self.cache[ip]
                if name != ip:
                    return f"{name} ({ip})"
                return ip
            
            if ip in self.resolving:
                return ip
            
            self.resolving.add(ip)

        # Trigger background resolution
        threading.Thread(target=self._resolve_async, args=(ip,), daemon=True).start()
        return ip

    def _resolve_async(self, ip):
        try:
            # Perform reverse DNS lookup
            hostname, _, _ = socket.gethostbyaddr(ip)
            name = hostname
        except Exception:
            # Custom label fallback for private IPs
            if ip.startswith('192.168.1.'):
                name = f'Local Device ({ip.split(".")[-1]})'
            elif ip.startswith('10.'):
                name = 'Local Host'
            else:
                name = ip

        with self.lock:
            self.cache[ip] = name
            if ip in self.resolving:
                self.resolving.remove(ip)
            logger.info('Resolved IP: %s -> %s', ip, name)


dns_resolver = DNSResolver()
