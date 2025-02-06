import sys
import argparse
import ipaddress
import socket
import signal
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP, ICMPerror
import graphviz
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Конфигурация
PING_TIMEOUT = 3
TRACE_TIMEOUT = 1  # Уменьшаем общий таймаут
MAX_RETRIES = 3    # Увеличиваем количество попыток
PACKET_DELAY = 0.1 # Задержка между пакетами
MAX_CONSECUTIVE_TIMEOUTS = 1
MAX_WORKERS = 40
MAX_HOPS = 30
INTERRUPTED = False

def signal_handler(sig, frame):
    global INTERRUPTED
    print("\nReceived interrupt, shutting down...")
    INTERRUPTED = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_local_ip():
    """Получаем IP адрес локального интерфейса"""
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def is_host_alive(target_ip, protocol, port=None):
    """Проверка доступности хоста с обработкой ICMP ошибок"""
    try:
        if protocol == "icmp":
            pkt = IP(dst=target_ip)/ICMP()
            resp = sr1(pkt, timeout=PING_TIMEOUT, verbose=0, retry=MAX_RETRIES)
            return resp and resp.haslayer(ICMP) and resp[ICMP].type == 0

        elif protocol == "tcp":
            pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=PING_TIMEOUT, verbose=0, retry=MAX_RETRIES)
            return resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12

        elif protocol == "udp":
            pkt = IP(dst=target_ip)/UDP(dport=port)
            resp = sr1(pkt, timeout=PING_TIMEOUT, verbose=0, retry=MAX_RETRIES)
            return not (resp and resp.haslayer(ICMPerror))

    except Exception:
        return False
    return False

def trace_route(target_ip, protocol, port=None):
    """Трассировка с улучшенным управлением таймаутами и задержками"""
    route = []
    last_hop = None
    try:
        for ttl in range(1, MAX_HOPS + 1):
            if INTERRUPTED:
                break

            start_time = time.time()
            response = None
            
            # Отправка с несколькими попытками
            for attempt in range(MAX_RETRIES):
                if INTERRUPTED:
                    break
                
                pkt = IP(dst=target_ip, ttl=ttl)
                if protocol == "icmp":
                    pkt /= ICMP()
                elif protocol == "tcp":
                    pkt /= TCP(dport=port, flags="S")
                elif protocol == "udp":
                    pkt /= UDP(dport=port)

                ans = sr1(pkt, timeout=TRACE_TIMEOUT, verbose=0, retry=0)
                remaining_time = TRACE_TIMEOUT - (time.time() - start_time)
                
                if ans is not None:
                    response = ans
                    break
                elif remaining_time > 0:
                    time.sleep(min(PACKET_DELAY, remaining_time))
            
            if not response:
                continue

            current_hop = response[IP].src
            
            # Фильтрация специальных адресов и дубликатов
            if (current_hop == target_ip or 
                current_hop.startswith("0.0.0.") or 
                current_hop == last_hop):
                continue
                
            route.append(current_hop)
            last_hop = current_hop

            # Ранний выход если достигли цели
            if current_hop == target_ip:
                break

        return (target_ip, tuple(route))
    except Exception as e:
        if not INTERRUPTED:
            print(f"Error tracing route to {target_ip}: {e}")
        return (target_ip, tuple())

def generate_dot_graph(results, filename):
    """Улучшенная визуализация с группировкой целей"""
    dot = graphviz.Digraph(
        graph_attr={
            'rankdir': 'LR',
            'dpi': '150',
            'nodesep': '0.5',
            'ranksep': '1.0',
            'splines': 'ortho'
        },
        node_attr={
            'shape': 'box',
            'style': 'rounded',
            'fontname': 'Helvetica',
            'fontsize': '10'
        }
    )

    dot.node("ATTACKER", label="ATTACKER", color='red', shape='doubleoctagon')
    
    # Собираем данные
    route_map = defaultdict(list)
    all_hops = set()
    target_ips = {target for target, _ in results}
    
    # Группируем цели по последнему хопу
    hop_groups = defaultdict(list)
    for target, route in results:
        if route:
            last_hop = route[-1]
            hop_groups[last_hop].append(target)
        else:
            hop_groups["DIRECT"].append(target)
        all_hops.update(route)
    
    # Создаем узлы только для промежуточных хостов
    hop_nodes = {}
    for hop in all_hops:
        node_id = f"n_{hop}"
        hop_nodes[hop] = node_id
        dot.node(node_id, label=hop)
    
    # Создаем групповые ноды для целей
    group_nodes = {}
    for last_hop, targets in hop_groups.items():
        if last_hop == "DIRECT":
            for target in targets:
                dot.node(target, label=target, shape='ellipse', color='blue')
            continue
            
        group_id = f"grp_{last_hop}"
        label = "\n".join(sorted(targets))
        dot.node(group_id, label=label, shape='ellipse', color='blue')
        group_nodes[last_hop] = group_id
    
    # Строим связи
    added_edges = set()
    for target, route in results:
        prev_node = "ATTACKER"
        
        for hop in route:
            current_node = hop_nodes[hop]
            if (prev_node, current_node) not in added_edges:
                dot.edge(prev_node, current_node)
                added_edges.add((prev_node, current_node))
            prev_node = current_node
        
        # Соединяем последний хоп с группой или целевым узлом
        if route:
            last_hop = route[-1]
            if last_hop in group_nodes:
                dot.edge(hop_nodes[last_hop], group_nodes[last_hop])
        else:
            dot.edge("ATTACKER", target)

    dot.render(filename, format='png', cleanup=True)

def main():
    parser = argparse.ArgumentParser(description="Network Tracer")
    parser.add_argument("--proto", required=True, choices=["icmp", "tcp", "udp"])
    parser.add_argument("-p", "--port", type=int)
    parser.add_argument("--target", required=True)
    parser.add_argument("-o", "--output", required=True)
    
    args = parser.parse_args()

    if args.proto in ["tcp", "udp"] and not args.port:
        print("Port required for TCP/UDP!")
        sys.exit(1)

    try:
        network = ipaddress.ip_network(args.target, strict=False)
        targets = [str(host) for host in network.hosts()]
    except ValueError as e:
        print(f"Invalid network: {str(e)}")
        sys.exit(1)

    active_targets = []
    print(f"Scanning {len(targets)} hosts...")
    
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(is_host_alive, ip, args.proto, args.port): ip for ip in targets}
            
            for i, future in enumerate(as_completed(futures), 1):
                if INTERRUPTED:
                    break
                if future.result():
                    active_targets.append(futures[future])
                print(f"Progress: {i}/{len(targets)} ({i/len(targets)*100:.1f}%)  ", end='\r')
    
        print(f"\nFound {len(active_targets)} active hosts. Starting trace...")
        
        results = []
        for i, ip in enumerate(active_targets, 1):
            if INTERRUPTED:
                break
            
            target_ip, route = trace_route(ip, args.proto, args.port)
            route_str = "attacker -> " + " -> ".join(route) + f" -> {target_ip}" if route else f"attacker -> {target_ip}"
            print(f"[{i}] {route_str}")
            results.append((target_ip, route))
            
            print(f"Trace progress: {i}/{len(active_targets)} ({i/len(active_targets)*100:.1f}%)  ", end='\r')

        generate_dot_graph(results, args.output)
        print(f"\nGraph saved to {args.output}.png")

    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()
