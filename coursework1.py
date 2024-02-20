import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext, ttk
import ipaddress
import socket
import threading
import requests
import nmap
from tkinter import filedialog

def get_local_ip():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip
    except socket.gaierror:
        return None

def display_local_ip():
    local_ip = get_local_ip()
    if local_ip:
        local_network = ipaddress.IPv4Network(f"{local_ip}/255.255.255.0", strict=False)
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Local IP Address: {local_network}\n")
        result_text.config(state=tk.DISABLED)
        ip_entry.delete(0, tk.END)  # Clear the entry for the user to input the target IP
    else:
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Unable to retrieve local IP address.\n")
        result_text.config(state=tk.DISABLED)

def get_oui_info(mac):
    # Extract the OUI (first 3 bytes) from the MAC address
    oui = mac[:8].replace(":", "").upper()

    # Make a request to the IEEE OUI Public Listing API
    url = f"https://api.macaddress.io/v1?apiKey=your_api_key&output=json&search={oui}"
    response = requests.get(url)
    data = response.json()

    # Check if the request was successful and the OUI information is available
    if response.status_code == 200 and "vendorDetails" in data:
        return data["vendorDetails"]["companyName"]
    else:
        return "Unknown"

def scan(ip, subnet_mask, scan_type):
    try:
        target_ip = ipaddress.IPv4Address(ip)
        local_ip = ipaddress.IPv4Address(get_local_ip())

        local_network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
        if target_ip in local_network:
            # Create an ARP layer packet and send it to the entire network
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            clients_list = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]

            # Filter out duplicate IPs
            unique_clients = []
            for client in clients_list:
                if client not in unique_clients:
                    unique_clients.append(client)

            if scan_type == "host_discovery":
                return [{"ip": client["ip"]} for client in unique_clients]
            elif scan_type == "network_scan":
                return unique_clients
        else:
            return []  # IP is not in the local network
    except ipaddress.AddressValueError:
        return []  # Return an empty list for an invalid IP address

def host_discovery(subnet_mask):
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Host Discovery Results\n")
    result_text.insert(tk.END, "-----------------------\n")

    local_ip = get_local_ip()
    local_network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)

    live_hosts = []
    total_hosts = len(list(local_network.hosts()))
    progress_bar["maximum"] = total_hosts

    for index, target_ip in enumerate(local_network.hosts(), start=1):
        if target_ip != local_ip:
            live_hosts.extend(scan(str(target_ip), subnet_mask, "host_discovery"))
            progress_bar["value"] = index
            window.update_idletasks()

    progress_bar["value"] = total_hosts  # Set progress bar to maximum after completion

    if live_hosts:
        result_text.insert(tk.END, "Live Hosts:\n")
        for host in live_hosts:
            ip = host['ip']
            mac = host.get('mac', 'Unknown')
            company_name = get_oui_info(mac)
            result_text.insert(tk.END, f"IP: {ip}, MAC: {mac}, Company: {company_name}\n")
    else:
        result_text.insert(tk.END, "No live hosts found.\n")

    result_text.config(state=tk.DISABLED)
    progress_bar["value"] = 0  # Reset progress bar value after completion

def host_discovery_button_click(subnet_mask):
    threading.Thread(target=host_discovery, args=(subnet_mask,), daemon=True).start()

def scan_network(subnet_mask):
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Network Scan Results\n")
    result_text.insert(tk.END, "---------------------\n")

    local_ip = get_local_ip()
    local_network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)

    live_hosts = []
    total_hosts = len(list(local_network.hosts()))
    progress_bar["maximum"] = total_hosts

    for index, target_ip in enumerate(local_network.hosts(), start=1):
        if target_ip != local_ip:
            live_hosts.extend(scan(str(target_ip), subnet_mask, "network_scan"))
            progress_bar["value"] = index
            window.update_idletasks()

    progress_bar["value"] = total_hosts  # Set progress bar to maximum after completion

    if live_hosts:
        result_text.config(state=tk.NORMAL)
        result_text.insert(tk.END, "Live Hosts:\n")
        for host in live_hosts:
            ip = host['ip']
            mac = host.get('mac', 'Unknown')
            company_name = get_oui_info(mac)
            result_text.insert(tk.END, f"IP: {ip}, MAC: {mac}, Company: {company_name}\n")
        result_text.config(state=tk.DISABLED)
    else:
        result_text.config(state=tk.NORMAL)
        result_text.insert(tk.END, "No live hosts found.\n")
        result_text.config(state=tk.DISABLED)
        progress_bar["value"] = 0  # Reset progress bar value after completion

def scan_network_button_click(subnet_mask):
    threading.Thread(target=scan_network, args=(subnet_mask,), daemon=True).start()

def port_scan(ip, port_range):
    result_text.config(state=tk.NORMAL)
    result_text.insert(tk.END, "Port Scan Results\n")
    result_text.insert(tk.END, "------------------\n")

    scanner = nmap.PortScanner()
    scanner.scan(ip, port_range)

    for host in scanner.all_hosts():
        result_text.insert(tk.END, f"Host: {host}\n")
        for proto in scanner[host].all_protocols():
            result_text.insert(tk.END, f"Protocol: {proto}\n")
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                result_text.insert(tk.END, f"Port: {port}, State: {state}\n")

    result_text.config(state=tk.DISABLED)

def port_scan_button_click(ip, port_range):
    threading.Thread(target=port_scan, args=(ip, port_range), daemon=True).start()

def export_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("JSON files", "*.json")])

    if file_path:
        with open(file_path, "w") as file:
            file.write(result_text.get("1.0", tk.END))

def export_results_button_click():
    threading.Thread(target=export_results, daemon=True).start()


# GUI Setup
window = tk.Tk()
window.title("Network Enumeration Tool")

ip_label = tk.Label(window, text="Target IP:")
ip_label.pack(pady=5)

ip_entry = tk.Entry(window)
ip_entry.pack(pady=5)

subnet_mask_label = tk.Label(window, text="Subnet Mask:")
subnet_mask_label.pack(pady=5)

subnet_mask_entry = tk.Entry(window)
subnet_mask_entry.pack(pady=5)

port_range_label = tk.Label(window, text="Port Range (e.g., 1-1024):")
port_range_label.pack(pady=5)

port_range_entry = tk.Entry(window)
port_range_entry.pack(pady=5)

local_ip_button = tk.Button(window, text="Display Local IP", command=display_local_ip)
local_ip_button.pack(pady=5)

host_discovery_button = tk.Button(window, text="Host Discovery", command=lambda: host_discovery_button_click(subnet_mask_entry.get()))
host_discovery_button.pack(pady=5)

scan_network_button = tk.Button(window, text="Network Scan", command=lambda: scan_network_button_click(subnet_mask_entry.get()))
scan_network_button.pack(pady=5)

port_scan_button = tk.Button(window, text="Port Scan", command=lambda: port_scan_button_click(ip_entry.get(), port_range_entry.get()))
port_scan_button.pack(pady=5)

export_button = tk.Button(window, text="Export Results", command=export_results_button_click)
export_button.pack(pady=5)

result_text = scrolledtext.ScrolledText(window, width=80, height=20, state=tk.DISABLED)
result_text.pack(pady=10)

progress_bar = ttk.Progressbar(window, orient=tk.HORIZONTAL, length=200, mode="determinate")
progress_bar.pack(pady=5)

window.mainloop()
