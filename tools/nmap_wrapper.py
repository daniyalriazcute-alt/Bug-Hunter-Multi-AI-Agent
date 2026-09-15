"""Nmap wrapper."""
from __future__ import annotations
import shutil
from config import MAX_RECON_PORTS

def nmap_scan(target: str, top_ports: int = MAX_RECON_PORTS) -> dict:
    if not shutil.which("nmap"):
        return {"error": "nmap binary not found in PATH"}
    try:
        import nmap
        nm = nmap.PortScanner()
        args = f"-sV -T4 --top-ports {top_ports} --open"
        nm.scan(hosts=target, arguments=args)
        out: dict = {"hosts": {}}
        for host in nm.all_hosts():
            ports = []
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    p = nm[host][proto][port]
                    ports.append({
                        "port": port, "protocol": proto,
                        "state": p.get("state"),
                        "service": p.get("name"),
                        "product": p.get("product"),
                        "version": p.get("version"),
                    })
            out["hosts"][host] = {"state": nm[host].state(), "ports": ports}
        return out
    except Exception as e:
        return {"error": str(e)}
