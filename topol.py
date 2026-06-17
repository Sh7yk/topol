#!/usr/bin/env python3
"""
nettopo.py — Network Topology Mapper for Internal Infrastructure Assessment
---------------------------------------------------------------------------
Requires root/CAP_NET_RAW. Usage:
  sudo python3 nettopo.py --target 192.168.1.0/24 --proto icmp -o report
  sudo python3 nettopo.py --target 10.0.0.0/24 --proto tcp -p 443 -o report --threads 30
  sudo python3 nettopo.py --target 10.0.0.1 --proto udp -p 53 -o report --format json
"""

import sys
import argparse
import ipaddress
import socket
import signal
import time
import json
import logging
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Lazy imports with graceful errors ────────────────────────────────────────
try:
    from scapy.all import conf as scapy_conf, sr1, RandShort
    from scapy.layers.inet import IP, ICMP, TCP, UDP, ICMPerror
    scapy_conf.verb = 0          # suppress all Scapy output globally
except ImportError:
    sys.exit("[!] scapy not found. Install: pip install scapy")

try:
    import graphviz
except ImportError:
    sys.exit("[!] graphviz not found. Install: pip install graphviz")

# ── Constants ─────────────────────────────────────────────────────────────────
PING_TIMEOUT        = 2
TRACE_TIMEOUT       = 1
MAX_RETRIES         = 2
MAX_HOPS            = 30
DEFAULT_THREADS     = 20       # conservative default; user may increase
PACKET_DELAY        = 0.05
TCP_SYN_FLAGS       = "S"
ICMP_ECHO_REPLY     = 0
ICMP_TIME_EXCEEDED  = 11
ICMP_PORT_UNREACH   = 3

# ── Logging ───────────────────────────────────────────────────────────────────
log = logging.getLogger("nettopo")

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    log.addHandler(handler)
    log.setLevel(level)

# ── Graceful shutdown ─────────────────────────────────────────────────────────
_stop_event = threading.Event()

def _signal_handler(sig, frame):
    log.warning("Interrupt received — finishing in-flight probes and exiting…")
    _stop_event.set()

signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class HopInfo:
    ip: str
    hostname: Optional[str]    = None
    rtt_ms: Optional[float]    = None   # round-trip time in ms
    icmp_type: Optional[int]   = None   # raw ICMP type from hop response

@dataclass
class HostResult:
    target_ip:  str
    hostname:   Optional[str]        = None
    alive:      bool                 = False
    protocol:   str                  = "icmp"
    port:       Optional[int]        = None
    route:      list[HopInfo]        = field(default_factory=list)
    firewall_hop: Optional[str]      = None   # first hop that sent admin-prohibit


# ── DNS resolver with cache ───────────────────────────────────────────────────
_dns_cache: dict[str, Optional[str]] = {}
_dns_lock  = threading.Lock()

def resolve_hostname(ip: str) -> Optional[str]:
    """Reverse-resolve an IP to a hostname (cached, never raises)."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        name = None
    with _dns_lock:
        _dns_cache[ip] = name
    return name


# ── Host discovery ────────────────────────────────────────────────────────────
def _build_probe(dst: str, proto: str, port: Optional[int], ttl: int = 64) -> IP:
    base = IP(dst=dst, ttl=ttl)
    if proto == "icmp":
        return base / ICMP(id=os.getpid() & 0xFFFF, seq=1)
    elif proto == "tcp":
        return base / TCP(sport=int(RandShort()), dport=port, flags=TCP_SYN_FLAGS)
    elif proto == "udp":
        return base / UDP(sport=int(RandShort()), dport=port)
    raise ValueError(f"Unknown protocol: {proto}")


def is_host_alive(ip: str, proto: str, port: Optional[int]) -> bool:
    """
    Probe a host using the selected protocol.
    Returns True if the host appears reachable.
    """
    if _stop_event.is_set():
        return False
    try:
        pkt  = _build_probe(ip, proto, port)
        resp = sr1(pkt, timeout=PING_TIMEOUT, verbose=0, retry=MAX_RETRIES)
        if resp is None:
            return False

        if proto == "icmp":
            return resp.haslayer(ICMP) and resp[ICMP].type == ICMP_ECHO_REPLY

        elif proto == "tcp":
            if resp.haslayer(TCP):
                # SYN-ACK (0x12) = open; RST (0x04) = closed but host exists
                flags = resp[TCP].flags
                return bool(flags & 0x12) or bool(flags & 0x04)
            return False

        elif proto == "udp":
            # For UDP: no ICMP port-unreachable → assume open/filtered (alive)
            # ICMP port-unreachable with the right inner dest → closed, but host exists
            if resp.haslayer(ICMPerror):
                inner = resp[ICMPerror]
                return inner.dst == ip
            return True

    except Exception as exc:
        log.debug("Discovery probe to %s failed: %s", ip, exc)
    return False


# ── Traceroute ────────────────────────────────────────────────────────────────
def trace_route(target_ip: str, proto: str, port: Optional[int],
                resolve: bool = True) -> list[HopInfo]:
    """
    Traceroute to target_ip using the selected protocol.
    Returns an ordered list of HopInfo objects (not including the target itself
    unless it responded to a TTL-limited probe).
    """
    route:    list[HopInfo]   = []
    seen_ips: set[str]        = set()

    for ttl in range(1, MAX_HOPS + 1):
        if _stop_event.is_set():
            break

        pkt  = _build_probe(target_ip, proto, port, ttl=ttl)
        t0   = time.perf_counter()
        resp = None

        for attempt in range(MAX_RETRIES):
            if _stop_event.is_set():
                break
            resp = sr1(pkt, timeout=TRACE_TIMEOUT, verbose=0, retry=0)
            if resp is not None:
                break
            if attempt < MAX_RETRIES - 1:
                time.sleep(PACKET_DELAY)

        if resp is None:
            log.debug("TTL %d → no response (target: %s)", ttl, target_ip)
            continue

        rtt_ms = (time.perf_counter() - t0) * 1000
        hop_ip = resp[IP].src

        # Skip duplicates (some routers answer multiple times)
        if hop_ip in seen_ips:
            continue
        seen_ips.add(hop_ip)

        icmp_type = resp[ICMP].type if resp.haslayer(ICMP) else None
        hostname  = resolve_hostname(hop_ip) if resolve else None

        hop = HopInfo(ip=hop_ip, hostname=hostname, rtt_ms=round(rtt_ms, 2),
                      icmp_type=icmp_type)
        route.append(hop)
        log.debug("TTL %2d → %-16s  rtt=%.1f ms  hostname=%s",
                  ttl, hop_ip, rtt_ms, hostname or "—")

        # Reached destination
        if hop_ip == target_ip:
            break

        # ICMP Admin Prohibited (type 3, codes 9/10/13) → firewall hop
        if icmp_type == ICMP_PORT_UNREACH:
            icmp_code = resp[ICMP].code if resp.haslayer(ICMP) else -1
            if icmp_code in (9, 10, 13):
                log.debug("Firewall hop detected at %s (code %d)", hop_ip, icmp_code)
                break

    return route


# ── Parallel scan ─────────────────────────────────────────────────────────────
def scan_network(targets: list[str], proto: str, port: Optional[int],
                 threads: int, resolve: bool) -> list[HostResult]:
    """
    Phase 1: discover live hosts in parallel.
    Phase 2: traceroute to each live host (also parallelised).
    """
    total   = len(targets)
    results: dict[str, HostResult] = {}

    # ── Phase 1: discovery ────────────────────────────────────────────────────
    log.info("Phase 1/2 — Scanning %d hosts (threads=%d, proto=%s, port=%s)",
             total, threads, proto, port)
    alive_ips: list[str] = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_map = {ex.submit(is_host_alive, ip, proto, port): ip
                      for ip in targets}
        done = 0
        for fut in as_completed(future_map):
            if _stop_event.is_set():
                break
            done += 1
            ip = future_map[fut]
            try:
                alive = fut.result()
            except Exception as exc:
                log.debug("Future for %s raised: %s", ip, exc)
                alive = False

            if alive:
                alive_ips.append(ip)
                hostname = resolve_hostname(ip) if resolve else None
                results[ip] = HostResult(target_ip=ip, hostname=hostname,
                                          alive=True, protocol=proto, port=port)
                log.debug("UP   %s (%s)", ip, hostname or "no rDNS")

            _print_progress("Scanning", done, total)

    print(file=sys.stderr)
    log.info("Found %d live host(s)", len(alive_ips))

    if not alive_ips:
        return []

    # ── Phase 2: traceroute ───────────────────────────────────────────────────
    log.info("Phase 2/2 — Tracing routes to %d host(s)", len(alive_ips))
    done = 0

    with ThreadPoolExecutor(max_workers=min(threads, len(alive_ips))) as ex:
        future_map2 = {ex.submit(trace_route, ip, proto, port, resolve): ip
                       for ip in alive_ips}
        for fut in as_completed(future_map2):
            if _stop_event.is_set():
                break
            done += 1
            ip    = future_map2[fut]
            route: list[HopInfo] = []
            try:
                route = fut.result()
            except Exception as exc:
                log.debug("Trace to %s raised: %s", ip, exc)

            results[ip].route = route

            # Detect firewall hop: any intermediate hop with admin-prohibit
            for hop in route:
                if hop.icmp_type == ICMP_PORT_UNREACH and hop.ip != ip:
                    results[ip].firewall_hop = hop.ip
                    break

            path_str = " → ".join(
                f"{h.ip}({h.rtt_ms:.0f}ms)" for h in route
            ) or "(direct)"
            log.debug("Route to %s: %s", ip, path_str)
            _print_progress("Tracing", done, len(alive_ips))

    print(file=sys.stderr)
    return list(results.values())


def _print_progress(label: str, done: int, total: int) -> None:
    pct = done / total * 100 if total else 0
    print(f"\r{label}: {done}/{total} ({pct:.0f}%)   ", end="", flush=True,
          file=sys.stderr)


# ── Output: JSON ──────────────────────────────────────────────────────────────
def export_json(results: list[HostResult], path: str) -> None:
    data = [asdict(r) for r in results]
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info("JSON saved → %s", path)


# ── Output: Graphviz DOT ──────────────────────────────────────────────────────
# Node colour palette by role
_COLORS = {
    "attacker":  {"color": "#c0392b", "fillcolor": "#fadbd8", "shape": "doubleoctagon"},
    "hop":       {"color": "#2c3e50", "fillcolor": "#eaecee",  "shape": "ellipse"},
    "firewall":  {"color": "#e67e22", "fillcolor": "#fef9e7",  "shape": "diamond"},
    "target":    {"color": "#1a5276", "fillcolor": "#d6eaf8",  "shape": "box"},
    "target_fw": {"color": "#922b21", "fillcolor": "#fdedec",  "shape": "box"},  # behind firewall
}

def _node_label(r: HostResult | HopInfo) -> str:
    """Build a multi-line Graphviz label."""
    if isinstance(r, HostResult):
        ip   = r.target_ip
        name = r.hostname
        port = f":{r.port}" if r.port else ""
        base = f"{ip}{port}"
    else:
        ip   = r.ip
        name = r.hostname
        rtt  = f"\n{r.rtt_ms:.0f} ms" if r.rtt_ms is not None else ""
        base = f"{ip}{rtt}"

    return f"{base}\n{name}" if name and name != ip else base


def generate_graph(results: list[HostResult], out_base: str,
                   fmt: str = "png") -> None:
    """
    Build a Graphviz directed graph:
    - ATTACKER → intermediate hops → targets
    - Firewall hops are coloured orange (diamond shape)
    - Targets behind a firewall hop are coloured red
    - RTT annotates each edge
    """
    g = graphviz.Digraph(
        "network_topology",
        graph_attr={
            "rankdir":  "LR",
            "dpi":      "150",
            "nodesep":  "0.6",
            "ranksep":  "1.2",
            "splines":  "ortho",
            "fontname": "Helvetica",
            "label":    "Network Topology Map",
            "labelloc": "t",
            "fontsize": "14",
        },
        node_attr={
            "style":    "filled",
            "fontname": "Helvetica",
            "fontsize": "9",
        }
    )

    # Attacker (source) node
    a = _COLORS["attacker"]
    g.node("__ATTACKER__", label="ATTACKER", **a)

    added_edges: set[tuple[str, str]] = set()
    added_hops:  set[str]             = set()

    # Collect all intermediate hops so we can pre-create them
    all_hops: dict[str, HopInfo] = {}
    firewall_hops: set[str]       = set()
    for r in results:
        if r.firewall_hop:
            firewall_hops.add(r.firewall_hop)
        for hop in r.route:
            if hop.ip != r.target_ip:
                all_hops[hop.ip] = hop

    # Create hop nodes
    for hop_ip, hop in all_hops.items():
        role  = "firewall" if hop_ip in firewall_hops else "hop"
        style = _COLORS[role]
        g.node(f"h_{hop_ip}", label=_node_label(hop), **style)

    # Create target nodes and edges
    for r in results:
        role  = "target_fw" if r.firewall_hop else "target"
        style = _COLORS[role]
        label = _node_label(r)
        g.node(f"t_{r.target_ip}", label=label, **style)

        prev = "__ATTACKER__"
        for hop in r.route:
            if hop.ip == r.target_ip:
                # Last hop IS the target — draw edge to target node
                _add_edge(g, added_edges, prev, f"t_{hop.ip}",
                          label=f"{hop.rtt_ms:.0f}ms" if hop.rtt_ms else "")
                prev = f"t_{hop.ip}"
            else:
                cur = f"h_{hop.ip}"
                _add_edge(g, added_edges, prev, cur,
                          label=f"{hop.rtt_ms:.0f}ms" if hop.rtt_ms else "")
                prev = cur

        # If route didn't end at target (e.g. firewall blocked), draw final edge
        if not r.route or r.route[-1].ip != r.target_ip:
            _add_edge(g, added_edges, prev, f"t_{r.target_ip}", label="")

    # Render
    try:
        g.render(out_base, format=fmt, cleanup=True)
        log.info("Graph saved → %s.%s", out_base, fmt)
    except graphviz.backend.execute.ExecutableNotFound:
        dot_path = out_base + ".gv"
        g.save(dot_path)
        log.warning("Graphviz binary not found. Raw DOT saved → %s", dot_path)
        log.warning("Install with: sudo apt install graphviz  OR  brew install graphviz")


def _add_edge(g: graphviz.Digraph, seen: set, src: str, dst: str,
              label: str = "") -> None:
    key = (src, dst)
    if key not in seen:
        seen.add(key)
        g.edge(src, dst, label=label, fontsize="7")


# ── Output: plain text route table ───────────────────────────────────────────
def print_route_table(results: list[HostResult]) -> None:
    print("\n" + "─" * 72)
    print(f"{'TARGET':<20} {'HOPS':>4}  {'ROUTE'}")
    print("─" * 72)
    for r in results:
        hops   = len(r.route)
        target = r.hostname or r.target_ip
        if r.port:
            target += f":{r.port}"
        route_str = " → ".join(
            (hop.hostname or hop.ip) + (f"[{hop.rtt_ms:.0f}ms]" if hop.rtt_ms else "")
            for hop in r.route
        ) or "(direct / no intermediate hops)"
        fw = f"  ⚠ firewall at {r.firewall_hop}" if r.firewall_hop else ""
        print(f"{target:<20} {hops:>4}  {route_str}{fw}")
    print("─" * 72 + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Network Topology Mapper — internal infrastructure assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--target",   required=True,
                   help="Target IP, CIDR range (e.g. 192.168.1.0/24), or comma-separated IPs")
    p.add_argument("--proto",    required=True, choices=["icmp", "tcp", "udp"],
                   help="Probe protocol")
    p.add_argument("-p", "--port", type=int, default=None,
                   help="Destination port (required for TCP/UDP)")
    p.add_argument("-o", "--output", required=True,
                   help="Output file base name (extensions added automatically)")
    p.add_argument("--format",   default="png", choices=["png", "svg", "pdf"],
                   help="Graph image format (default: png)")
    p.add_argument("--threads",  type=int, default=DEFAULT_THREADS,
                   help=f"Worker thread count (default: {DEFAULT_THREADS})")
    p.add_argument("--no-dns",   action="store_true",
                   help="Skip reverse-DNS resolution of hops")
    p.add_argument("--json",     action="store_true",
                   help="Also export results as JSON")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show debug-level output")
    return p


def parse_targets(raw: str) -> list[str]:
    """Accept CIDR, single IP, or comma-separated IPs."""
    targets: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        try:
            net = ipaddress.ip_network(part, strict=False)
            targets.extend(str(h) for h in net.hosts())
        except ValueError:
            sys.exit(f"[!] Invalid target: '{part}'")
    return targets


def main() -> None:
    parser  = build_parser()
    args    = parser.parse_args()
    setup_logging(args.verbose)

    if args.proto in ("tcp", "udp") and args.port is None:
        parser.error("--port is required for TCP/UDP probes")

    if os.geteuid() != 0:
        log.warning("Not running as root — raw socket probes may fail")

    targets = parse_targets(args.target)
    if not targets:
        sys.exit("[!] No valid targets derived from input")

    log.info("Targets: %d host(s)  |  Protocol: %s  |  Port: %s",
             len(targets), args.proto, args.port or "N/A")

    results = scan_network(
        targets  = targets,
        proto    = args.proto,
        port     = args.port,
        threads  = args.threads,
        resolve  = not args.no_dns,
    )

    if not results:
        log.warning("No live hosts found — nothing to graph")
        sys.exit(0)

    print_route_table(results)
    generate_graph(results, args.output, fmt=args.format)

    if args.json:
        export_json(results, args.output + ".json")

    log.info("Done. %d host(s) mapped.", len(results))


if __name__ == "__main__":
    main()
