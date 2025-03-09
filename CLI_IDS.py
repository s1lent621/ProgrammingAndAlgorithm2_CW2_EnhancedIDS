import os
import platform
import threading
import time
from scapy.all import sniff, IP

# IDS Configuration
alert_threshold = 5  # Number of packets before flagging as suspicious
ip_count = {}
blocked_ips = set()
log_file = "blocked_ips.log"
sniffing = False
sniff_thread = None

# Function to log blocked IPs
def log_blocked_ip(ip):
    with open(log_file, "a") as file:
        file.write(ip + "\n")

# Function to block an IP
def block_ip(ip):
    if ip in blocked_ips:
        print(f"⚠ IP {ip} is already blocked!")
        return  

    system = platform.system()
    if system == "Linux":
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    elif system == "Windows":
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    
    blocked_ips.add(ip)
    log_blocked_ip(ip)
    log_alert(f"🚫 IP {ip} has been blocked!")

# Function to unblock an IP
def unblock_ip(ip):
    if ip in blocked_ips:
        system = platform.system()
        if system == "Linux":
            while True:  
                result = os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
                if result != 0:  
                    break
        elif system == "Windows":
            os.system(f"netsh advfirewall firewall delete rule name=\"Block {ip}\" remoteip={ip}")

        blocked_ips.remove(ip)
        log_alert(f"✅ IP {ip} has been unblocked!")
    else:
        log_alert(f"❌ IP {ip} not found in blocked list.")

# Function to detect attacks
def packet_callback(packet):
    if not sniffing:
        return

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1

        if ip_count[src_ip] > alert_threshold:
            log_alert(f"⚠ Suspicious activity detected from {src_ip}")
            block_ip(src_ip)

# Function to log alerts in CLI format
def log_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

# Function to start IDS
def start_sniffing():
    global sniffing, sniff_thread
    if sniffing:
        log_alert("⚠ IDS is already running!")
        return
    
    sniffing = True
    sniff_thread = threading.Thread(target=sniff, kwargs={"prn": packet_callback, "store": 0, "iface": None, "filter": "ip"}, daemon=True)
    sniff_thread.start()
    log_alert("🔍 IDS Started (Listening on ALL interfaces)")

# Function to stop IDS
def stop_sniffing():
    global sniffing
    if not sniffing:
        log_alert("⚠ IDS is not running!")
        return
    
    sniffing = False
    log_alert("⛔ IDS Stopped!")

# CLI Menu
def menu():
    while True:
        print("\n" + "="*50)
        print("🔹 Intrusion Detection System (IDS) 🔹")
        print("="*50)
        print("[1] Start IDS")
        print("[2] Stop IDS")
        print("[3] Block an IP")
        print("[4] Unblock an IP")
        print("[5] Show Blocked IPs")
        print("[6] Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            start_sniffing()
        elif choice == "2":
            stop_sniffing()
        elif choice == "3":
            ip = input("Enter IP to block: ")
            block_ip(ip)
        elif choice == "4":
            ip = input("Enter IP to unblock: ")
            unblock_ip(ip)
        elif choice == "5":
            print("\nBlocked IPs:")
            if blocked_ips:
                for ip in blocked_ips:
                    print(f"- {ip}")
            else:
                print("No IPs are blocked.")
        elif choice == "6":
            stop_sniffing()
            print("Exiting IDS... Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

# Run CLI Menu
if __name__ == "__main__":
    menu()
