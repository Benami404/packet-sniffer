import tkinter as tk
from tkinter import ttk, messagebox
import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, get_if_list

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("800x600")

        self.sniffer = None
        self.capturing = False
        self.thread = None

        # Interface Dropdown
        self.interface_label = tk.Label(root, text="Select Interface:")
        self.interface_label.pack(pady=5)

        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(root, textvariable=self.interface_var)
        self.interface_dropdown['values'] = get_if_list()
        self.interface_dropdown.pack(pady=5)

        # Filter Entry
        self.filter_label = tk.Label(root, text="Filter (e.g., 'tcp or udp'):")
        self.filter_label.pack(pady=5)

        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(root, textvariable=self.filter_var, width=50)
        self.filter_entry.pack(pady=5)

        # Start/Stop Buttons
        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture, bg="green", fg="white")
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_capture, bg="red", fg="white", state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Packet Display
        self.packet_list = tk.Listbox(root, width=100, height=25)
        self.packet_list.pack(pady=10)

        # Clear Packets Button
        self.clear_button = tk.Button(root, text="Clear Packets", command=self.clear_packets)
        self.clear_button.pack(pady=5)

        # Logging Checkbox
        self.log_var = tk.BooleanVar()
        self.log_checkbox = tk.Checkbutton(root, text="Enable Logging", variable=self.log_var)
        self.log_checkbox.pack(pady=5)

    def start_capture(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.thread = threading.Thread(target=self.capture_packets, args=(interface,), daemon=True)
        self.thread.start()

    def stop_capture(self):
        self.capturing = False
        if self.thread and self.thread.is_alive():
            self.thread.join()

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def capture_packets(self, interface):
        sniff(iface=interface, prn=self.process_packet, store=False, stop_filter=lambda _: not self.capturing)

    def process_packet(self, packet):
        details = "Unknown Packet Type"

        if packet.haslayer(Ether):
            ethernet = packet[Ether]
            details = f"Ethernet: {ethernet.src} -> {ethernet.dst}"

        if packet.haslayer(IP):
            ip = packet[IP]
            details += f", IP: {ip.src} -> {ip.dst}"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            details += f", TCP Port: {tcp.sport} -> {tcp.dport}"

        if packet.haslayer(UDP):
            udp = packet[UDP]
            details += f", UDP Port: {udp.sport} -> {udp.dport}"

        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            details += f", Raw Data: {raw_data[:20]}..."  # Show first 20 bytes

        self.packet_list.insert(tk.END, details)

    def clear_packets(self):
        self.packet_list.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
