import time
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw
from typing import Optional
import logging

class Decoder:
    def __init__(self, interface: Optional[str] = None):
        """Decode Ethernet frames incoming from a given interface.

        :param interface: Interface from which frames will be captured and decoded.
        """
        self.interface = interface
        self.packet_num = 0

    def _process_packet(self, packet):
        """Process a single packet captured by Scapy.

        :param packet: A raw packet captured by Scapy.
        """
        self.packet_num += 1
        details = f"[>] Packet #{self.packet_num}: "

        # Decode Ethernet Layer
        if packet.haslayer(Ether):
            ethernet = packet[Ether]
            details += f"Ethernet: {ethernet.src} -> {ethernet.dst}"

        # Decode IP Layer
        if packet.haslayer(IP):
            ip = packet[IP]
            details += f", IP: {ip.src} -> {ip.dst}"

        # Decode TCP Layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            details += f", TCP Port: {tcp.sport} -> {tcp.dport}"

        # Decode UDP Layer
        if packet.haslayer(UDP):
            udp = packet[UDP]
            details += f", UDP Port: {udp.sport} -> {udp.dport}"

        # Decode Raw Data Layer
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            details += f", Raw Data: {raw_data[:20]}..."  # Display first 20 bytes

        print(details)

    def execute(self):
        """Capture and process packets using Scapy.

        Captures packets from the specified interface and processes them one by one.
        """
        print(f"[>>>] Starting packet capture on interface {self.interface}... Press Ctrl-C to stop.")
        try:
            sniff(iface=self.interface, prn=self._process_packet, store=False)
        except PermissionError:
            print("[!] Permission denied. Run with administrative privileges.")
        except KeyboardInterrupt:
            print("\n[!] Packet capture stopped.")


class PacketSniffer:
    def __init__(self, log_file: Optional[str] = None):
        """Monitor a network interface for incoming data and decode it.

        :param log_file: Optional file path to save captured packets.
        """
        self._observers = list()
        self.log_file = log_file

        if log_file:
            logging.basicConfig(
                filename=log_file, level=logging.INFO,
                format="%(asctime)s - %(message)s"
            )
        else:
            logging.basicConfig(
                level=logging.INFO, format="%(asctime)s - %(message)s"
            )

    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded frames.

        :param observer: Any object that implements the interface
        defined by the Output abstract base-class.
        """
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded frame to all registered observers for further
        processing/output.
        """
        [observer.update(*args, **kwargs) for observer in self._observers]

    def listen(self, interface: str) -> None:
        """Start listening to packets on the given interface.

        :param interface: Interface from which packets will be captured and decoded.
        """
        decoder = Decoder(interface=interface)
        try:
            decoder.execute()
        except KeyboardInterrupt:
            print("\n[!] Packet capture stopped.")
            logging.info("Packet capture stopped by user.")
