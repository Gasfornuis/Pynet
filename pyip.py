import subprocess
import tqdm
import re
import ipaddress
import concurrent.futures
import threading

valid_ips = []
ip_list = []
lock = threading.Lock()

def get_subnet_mask():
    while True:
        try:
            subnet_mask = input("subnet mask (/24 /16 /...): /")
            subnet_mask = int(subnet_mask)
            if subnet_mask > 32 or subnet_mask < 1:
                print ("an invalid number was entered")
                continue
            return subnet_mask
        except ValueError:
            print("Value Error: the entered value has to be a number")

def make_ip_list(subnet_mask):
    while True:
        subnet_address = input("subnet address: ")
        try:
            network = ipaddress.ip_network(f"{subnet_address}/{subnet_mask}", strict=False)
            for ip in network.hosts():
                ip_list.append(str(ip))                
            print(f"Found {len(ip_list)} usable IPs")
            break    
        except ValueError as e:
            print(f"Invalid subnet: {e}")
        
def ping_ip(host):
    ping = subprocess.Popen(
        ["ping", "-c", "1", host],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    print(f"pinged {host}")
    response = ping.communicate()[0]
    if ping.returncode == 0:  #
        print(f"{host} responded")
        with lock:
            valid_ips.append(host)
    else:
        print(f"{host} did not respond")

def ping_full_list(ip_list, threads=100):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(ping_ip, ip_list)
    

if __name__ == "__main__":
    make_ip_list(get_subnet_mask())
    print(ip_list)
    ping_full_list(ip_list)
    print(valid_ips)
