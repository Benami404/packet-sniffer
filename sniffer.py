import argparse
import ctypes
import logging
from core import PacketSniffer
from output import OutputToScreen

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description="Enhanced Network Packet Sniffer")

    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to capture packets from (monitors all if not specified)."
    )

    parser.add_argument(
        "-d", "--data",
        action="store_true",
        help="Display raw packet data in the output."
    )

    parser.add_argument(
        "-f", "--filter",
        type=str,
        default=None,
        help="Filter packets by protocol, IP, or port (e.g., 'ipv4.src=192.168.0.1')."
    )

    parser.add_argument(
        "-l", "--log",
        type=str,
        default=None,
        help="File path to save captured packet logs (optional)."
    )

    parser.add_argument(
        "-s", "--stats",
        type=int,
        default=0,
        help="Interval (in seconds) to display capture statistics (0 to disable)."
    )

    return parser.parse_args()


def parse_filter(filter_str):
    """Parse the filter string into a dictionary.

    :param filter_str: Filter string in the format 'protocol.field=value'.
    :return: A dictionary representing the filter conditions.
    """
    if not filter_str:
        return None

    try:
        filters = {}
        for condition in filter_str.split(","):
            proto_field, value = condition.split("=")
            filters[proto_field.strip()] = value.strip()
        return filters
    except ValueError:
        raise SystemExit("Error: Invalid filter format. Use 'protocol.field=value'.")


def main():
    if not is_admin():
        raise SystemExit("Error: Permission denied. This application requires administrative privileges to run.")

    args = parse_arguments()
    packet_filter = parse_filter(args.filter)

    # Initialize the PacketSniffer and output observer
    sniffer = PacketSniffer(log_file=args.log)
    OutputToScreen(sniffer, display_data=args.data, stats_interval=args.stats)

    try:
        print("[>>>] Starting packet capture... Press Ctrl-C to stop.")
        for packet in sniffer.listen(interface=args.interface):
            if packet_filter:
                # Apply the filter logic here manually if needed
                pass
    except KeyboardInterrupt:
        print("\n[!] Aborting packet capture...")
        logging.info("Packet capture stopped by user.")


if __name__ == "__main__":
    main()
