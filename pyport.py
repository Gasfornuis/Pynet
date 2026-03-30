#imports
import os
import socket
import threading
import tqdm

number_of_threads = 32
open_ports = []
threads = []
lock = threading.Lock()
stop_threads = threading.Event()

def is_Valid_Input(user_input):
    is_valid = False
    if len(user_input) >= 1:
        is_valid = True
    return is_valid

def create_Threads(target_function, target_ip, port_range):
    progress_bar = tqdm.tqdm(port_range)
    port_chunk = len(port_range) // number_of_threads
    try:
        for i in range(number_of_threads):
            start = port_chunk * i
            end = (i + 1) * port_chunk if i != number_of_threads - 1 else len(port_range)
            thread = threading.Thread(target=target_function, args=(target_ip, port_range[start:end], progress_bar))
            thread.daemon = True
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        threads.clear()   
    except KeyboardInterrupt:
        stop_threads.set()
        progress_bar.close()
        print("\nExiting...")
def get_Ip():
    ip_input = input("target ip: ")
    while is_Valid_Input(ip_input) == False:
        print("not a valid input")
        ip_input = input("target ip: ")
    return ip_input

def get_Port_Range():
    while True:
        try:
            port_start = input("port range start:")
            port_end = input("port range end")
            if not port_start.isdigit() or not port_end.isdigit():
                print("both the start and end of the range have to be numbers")
                continue
            port_start = int(port_start)
            port_end = int(port_end)
            if port_start < 1 or port_end > 65535 or port_start > port_end:
                    print("please enter a range between 1 and 65535")
                    continue
            port_end += 1
            port_range = range(port_start, port_end)
            return port_range
        except ValueError:
            print("Value error, port range needs 2 numbers")
        
def get_Packet_Type():
    input_packet_type = input("packet type?(TCP)/...")
    supported_packets = ("TCP", "syn")
    while is_Valid_Input(input_packet_type) == False or input_packet_type not in supported_packets:
        print("not a supported packet type")
        input_packet_type = input("packet type?(TCP/...)")
    match input_packet_type:
        case "TCP":
            return "TCP"

def send_Requests(target_ip, port_range, packet_type):
     match packet_type:
        case "TCP":
            create_Threads(send_TCP, target_ip, port_range)

def send_TCP(target_ip, port_range, progress_bar):
    for port in port_range:
        if stop_threads.is_set():
            break
        try:
            packet = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            packet.settimeout(0.5)
            #print(f"sending TCP packet to {target_ip} on port {port}") #printing every port for debugging
            port_is_closed = packet.connect_ex((target_ip, port))
            if port_is_closed == 0:
                with lock:
                    open_ports.append(port)
                #print(f"port {port} is open!") #printing open port when found for debugging
            packet.close()
            progress_bar.update(1)
        except socket.error:
            print (f"unable to reach {target_ip}")

def save_results():
    save_ports = input("save ports? (y/n) ")
    match save_ports:
        case "y":
            with open("open_ports.txt", "w") as port_file:
                for port in open_ports:
                    port_file.write(f"{port}\n")
                port_file.close()
        case _:
            return

def main():
    target_ip = get_Ip()
    scan_all_ports = input("do you want to scan all ports?(y/n) ")
    match scan_all_ports:
        case "n": 
            port_range = get_Port_Range()
        case _:
            port_range = range(1, 65536)
    packet_type = get_Packet_Type()
    send_Requests(target_ip, port_range, packet_type)
    print(open_ports)
    save_results()


if __name__ == "__main__":
    main()
