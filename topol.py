import sys
import argparse
import ipaddress
import time
import socket
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import graphviz
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Конфигурация
PING_TIMEOUT = 1
TRACE_TIMEOUT = 4
MAX_RETRIES = 1
MAX_CONSECUTIVE_TIMEOUTS = 3
MAX_WORKERS = 10

def get_local_ip(interface=None):
    """Получаем IP адрес указанного интерфейса"""
    try:
        if interface:
            return get_if_addr(interface)
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def is_host_alive(target_ip, protocol, port=None, iface=None):
    """Проверка доступности хоста"""
    try:
        if protocol == "icmp":
            pkt = IP(dst=target_ip)/ICMP()
        elif protocol == "tcp":
            pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        elif protocol == "udp":
            pkt = IP(dst=target_ip)/UDP(dport=port)

        resp = sr1(pkt, timeout=PING_TIMEOUT, verbose=0, retry=MAX_RETRIES, iface=iface)
        return resp is not None
    except Exception:
        return False

def trace_route(target_ip, protocol, port=None, iface=None):
    """Трассировка маршрута с использованием указанного интерфейса"""
    route = []
    try:
        for ttl in range(1, 30):
            pkt = IP(dst=target_ip, ttl=ttl)
            if protocol == "icmp":
                pkt /= ICMP()
            elif protocol == "tcp":
                pkt /= TCP(dport=port, flags="S")
            elif protocol == "udp":
                pkt /= UDP(dport=port)

            ans = sr1(pkt, timeout=TRACE_TIMEOUT, verbose=0, iface=iface)
            if ans is None:
                continue

            current_hop = ans[IP].src
            route.append(current_hop)

            if current_hop == target_ip:
                break

        return (target_ip, tuple(route))
    except Exception:
        return (target_ip, tuple())

def generate_dot_graph(results, source_ip, filename):
    """Визуализация полной трассировки с умной группировкой целей"""
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

    # Добавление исходного узла
    dot.node(source_ip, label=source_ip, color='red', shape='doubleoctagon')

    # Словари для данных
    route_map = defaultdict(list)  # Все маршруты по пути
    target_groups = defaultdict(list)  # Группировка целей
    all_hops = set()  # Все уникальные хосты

    # Сбор данных
    for target, route in results:
        route_map[route].append(target)
        if route:
            last_hop = route[-1]
            target_groups[last_hop].append(target)
            all_hops.update(route)
        else:
            # Для целей без маршрута считаем их отдельными хостами
            target_groups[target].append(target)
            all_hops.add(target)

    # Создаем все узлы
    hop_nodes = {}
    for hop in all_hops:
        node_name = f"n_{hop}"
        hop_nodes[hop] = node_name
        dot.node(node_name, label=hop)

    # Строим связи между узлами
    added_edges = set()
    for route, targets in route_map.items():
        if not route:  # Прямое подключение к source
            for target in targets:
                dot.edge(source_ip, hop_nodes[target])
            continue
            
        prev_node = source_ip
        for hop in route:
            current_node = hop_nodes[hop]
            edge_key = (prev_node, current_node)
            
            if edge_key not in added_edges:
                dot.edge(prev_node, current_node)
                added_edges.add(edge_key)
            
            prev_node = current_node

    # Добавляем групповые ноды только для множественных целей
    for last_hop, targets in target_groups.items():
        if len(targets) == 1:
            continue  # Пропускаем одиночные цели
            
        # Создаем групповую ноду
        group_node = f"grp_{last_hop}"
        dot.node(
            group_node,
            label="\n".join(sorted(targets)),
            shape='ellipse',
            color='blue',
            fontcolor='navy'
        )
        
        # Соединяем с последним хопом
        if last_hop in hop_nodes:
            dot.edge(hop_nodes[last_hop], group_node)
        else:
            dot.edge(source_ip, group_node)

    dot.render(filename, format='png', cleanup=True)

def main():
    parser = argparse.ArgumentParser(description="Network Tracer")
    parser.add_argument("--proto", required=True, choices=["icmp", "tcp", "udp"])
    parser.add_argument("-p", "--port", type=int)
    parser.add_argument("--target", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-i", "--interface", help="Network interface to use")
    
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

    source_ip = get_local_ip(args.interface)
    results = []
    
    # Многопоточная проверка доступности
    active_targets = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(is_host_alive, ip, args.proto, args.port, args.interface): ip for ip in targets}
        
        print(f"Scanning {len(targets)} hosts...", end='\r')
        for future in as_completed(futures):
            if future.result():
                active_targets.append(futures[future])

    # Многопоточная трассировка
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(trace_route, ip, args.proto, args.port, args.interface) for ip in active_targets]
        
        print(f"\nTracing {len(active_targets)} active hosts...")
        for future in as_completed(futures):
            results.append(future.result())
            print(f"Progress: {len(results)}/{len(active_targets)}", end='\r')

    generate_dot_graph(results, source_ip, args.output)
    print(f"\nGraph saved to {args.output}.png")

if __name__ == "__main__":
    main()
