"""
Port + service/version scanning.

Primary engine: nmap (via python-nmap) run with -sV for service/version
detection, which is what the CVE matcher needs. Falls back to a plain
TCP-connect scan (stdlib `socket`) if the nmap binary isn't available,
which still finds open ports but without version fingerprinting.
"""
import socket
import concurrent.futures
import nmap
from scanner.authorization import require_authorization


def _parse_port_range(port_range: str):
    """'1-1024' -> (1, 1024); '22,80,443' -> explicit list handled by caller."""
    if "-" in port_range:
        start, end = port_range.split("-")
        return int(start), int(end)
    return None


def nmap_scan(target: str, port_range: str = "1-1024"):
    """Run an nmap -sV scan. Returns list of dicts, one per open port."""
    require_authorization(target)
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, ports=port_range, arguments="-sV -T4 --open")

    results = []
    if target not in scanner.all_hosts():
        # nmap sometimes reports the resolved IP instead of the hostname
        hosts = scanner.all_hosts()
        if not hosts:
            return results
        target = hosts[0]

    for proto in scanner[target].all_protocols():
        ports = scanner[target][proto].keys()
        for port in sorted(ports):
            info = scanner[target][proto][port]
            if info.get("state") != "open":
                continue
            results.append({
                "port": port,
                "protocol": proto,
                "state": info.get("state"),
                "service_name": info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "banner": (info.get("product", "") + " " + info.get("version", "")).strip(),
            })
    return results


def socket_scan(target: str, port_range: str = "1-1024", max_workers: int = 200):
    """Fallback plain TCP-connect scan, no service fingerprinting."""
    require_authorization(target)
    start, end = _parse_port_range(port_range)
    open_ports = []

    def check(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                if s.connect_ex((target, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = ""
                    return {
                        "port": port, "protocol": "tcp", "state": "open",
                        "service_name": service, "product": "", "version": "",
                        "banner": "",
                    }
        except socket.error:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for result in pool.map(check, range(start, end + 1)):
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda r: r["port"])


def scan_target(target: str, port_range: str = "1-1024"):
    """Try nmap first, gracefully fall back to the socket scanner."""
    try:
        results = nmap_scan(target, port_range)
        if results or _nmap_available():
            return results, "nmap"
    except Exception:
        pass
    return socket_scan(target, port_range), "socket"


def _nmap_available():
    try:
        nmap.PortScanner()
        return True
    except Exception:
        return False
