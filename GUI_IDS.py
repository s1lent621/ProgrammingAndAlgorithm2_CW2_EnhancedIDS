import tkinter as tk
from tkinter import scrolledtext, simpledialog
from scapy.all import sniff, IP
import threading
import os
import platform

# IDS Configuration
alert_threshold = 10  # Packets before blocking
ip_count = {}
blocked_ips = set()
log_file = "blocked_ips.log"
sniff_thread = None

# Function to log blocked IPs to a file
def log_blocked_ip(ip):
    with open(log_file, "a") as file:
        file.write(ip + "\n")

# Function to block an IP (Linux & Windows)
def block_ip(ip):
    if ip in blocked_ips:
        return  # Already blocked

    system = platform.system()
    if system == "Linux":
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    elif system == "Windows":
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    
    blocked_ips.add(ip)
    log_blocked_ip(ip)
    update_blocked_ip_list()
    log_alert(f"🚫 IP {ip} has been blocked!")

# Function to unblock an IP
def unblock_ip():
    ip = simpledialog.askstring("Unblock IP", "Enter IP to unblock:")
    if ip and ip in blocked_ips:
        system = platform.system()
        if system == "Linux":
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        elif system == "Windows":
            os.system(f"netsh advfirewall firewall delete rule name=\"Block {ip}\" remoteip={ip}")
        
        blocked_ips.remove(ip)
        update_blocked_ip_list()
        log_alert(f"✅ IP {ip} has been unblocked!")
    else:
        log_alert("❌ Invalid IP or not blocked.")

# Function to detect attacks
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1

        # Detect excessive packets (port scan, DoS)
        if ip_count[src_ip] > alert_threshold:
            log_alert(f"⚠ Suspicious activity from {src_ip}")
            block_ip(src_ip)

# Function to log alerts in GUI
def log_alert(message):
    log_box.insert(tk.END, message + "\n")
    log_box.yview(tk.END)  # Auto-scroll to latest message

# Function to start packet sniffing
def start_sniffing():
    sniff(prn=packet_callback, store=0, filter="ip", count=0)

# Run sniffing in a separate thread
def start_thread():
    global sniff_thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    log_alert("🔍 IDS Started: Monitoring Traffic...")
    start_button.config(state="disabled")  # Disable Start IDS button
    stop_button.config(state="normal")   # Enable Stop IDS button

# Function to stop sniffing
def stop_sniffing():
    global sniff_thread
    if sniff_thread is not None:
        sniff_thread = None  # Stop sniffing by breaking the thread
        log_alert("🛑 IDS Stopped: No longer monitoring traffic.")
    start_button.config(state="normal")  # Enable Start IDS button
    stop_button.config(state="disabled")  # Disable Stop IDS button

# Update blocked IP list in the GUI
def update_blocked_ip_list():
    blocked_ips_list.delete(0, tk.END)
    for ip in blocked_ips:
        blocked_ips_list.insert(tk.END, ip)

# GUI Setup
root = tk.Tk()
root.title("Advanced IDS with Auto-Blocking & Unblock Feature")
root.geometry("600x500")

# Logs Section
log_box = scrolledtext.ScrolledText(root, width=70, height=10)
log_box.pack(pady=10)

# Blocked IP List
blocked_ips_list = tk.Listbox(root, width=70, height=6)
blocked_ips_list.pack(pady=10)

# Buttons Section
start_button = tk.Button(root, text="Start IDS", command=start_thread, bg="green", fg="white")
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop IDS", command=stop_sniffing, bg="red", fg="white", state="disabled")
stop_button.pack(pady=5)

block_button = tk.Button(root, text="Block IP", command=lambda: block_ip(simpledialog.askstring("Block IP", "Enter IP to block:")), bg="orange", fg="white")
block_button.pack(pady=5)

unblock_button = tk.Button(root, text="Unblock IP", command=unblock_ip, bg="blue", fg="white")
unblock_button.pack(pady=5)

root.mainloop()
