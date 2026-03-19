import subprocess
import ipaddress
import concurrent.futures
import threading
import argparse
import platform

valid_ips = []
lock = threading.Lock()

def get_ping_command(host, timeout):
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        return ["ping", "-c", "1", "-W", str(timeout), host]
    
def make_ip_list(subnet):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        print(f"Found {len(ip_list)} usable IPs")
        return ip_list
    except ValueError as e:
        print(f"Invalid subnet: {e}")
        exit(1)
        
def ping_ip(host, timeout):
    cmd = get_ping_command(host, timeout)
    try:
        result = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        if result.returncode == 0:  
            print(f"{host} responded")
            with lock:
                valid_ips.append(host)
    except Exception:
        pass
    
def ping_full_list(ip_list, threads, timeout):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(lambda ip: ping_ip(ip, timeout), ip_list)
    
def main():
    parser = argparse.ArgumentParser(description="python ping sweeper")
    parser.add_argument("subnet", help="target subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("-t", "--threads", type=int, help="number of threads used (default: 100)", default=100)
    parser.add_argument("--timeout", type=int, help="timeout per ping in seconds (default: 1)", default=1)
    args = parser.parse_args()
    
    ip_list = make_ip_list(args.subnet)
    ping_full_list(ip_list, args.threads, args.timeout)
    print("\nResponsive hosts:")
    for ip in valid_ips:
        print(ip)

if __name__ == "__main__":
    main()
