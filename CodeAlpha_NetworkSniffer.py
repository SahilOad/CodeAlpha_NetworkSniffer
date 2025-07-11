# Import necessary modules from scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether

# Define a callback function to process each captured packet
def packet_callback(packet):
    """
    This function is called for every packet captured.
    It analyzes the packet and prints relevant information.
    """
    print("\n--- New Packet Captured ---")

    # Check for Ethernet layer
    if Ether in packet:
        print(f"  MAC Source: {packet[Ether].src}")
        print(f"  MAC Destination: {packet[Ether].dst}")
        print(f"  EtherType: {packet[Ether].type}") # 0x800 for IP, 0x806 for ARP

    # Check for IP layer
    if IP in packet:
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto}") # 6 for TCP, 17 for UDP, 1 for ICMP

        # Determine the protocol and print specific details
        if packet[IP].proto == 6: # TCP
            print("  Protocol: TCP")
            if TCP in packet:
                print(f"    Source Port: {packet[TCP].sport}")
                print(f"    Destination Port: {packet[TCP].dport}")
                print(f"    Flags: {packet[TCP].flags}")
                # Check for payload in TCP
                if Raw in packet:
                    print(f"    Payload (TCP): {packet[Raw].load}")
                elif packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
                    print(f"    Payload (TCP, raw): {bytes(packet[TCP].payload)}")

        elif packet[IP].proto == 17: # UDP
            print("  Protocol: UDP")
            if UDP in packet:
                print(f"    Source Port: {packet[UDP].sport}")
                print(f"    Destination Port: {packet[UDP].dport}")
                # Check for payload in UDP
                if Raw in packet:
                    print(f"    Payload (UDP): {packet[Raw].load}")
                elif packet.haslayer(UDP) and len(packet[UDP].payload) > 0:
                    print(f"    Payload (UDP, raw): {bytes(packet[UDP].payload)}")

        elif packet[IP].proto == 1: # ICMP
            print("  Protocol: ICMP")
            if ICMP in packet:
                print(f"    ICMP Type: {packet[ICMP].type}")
                print(f"    ICMP Code: {packet[ICMP].code}")
                # Check for payload in ICMP
                if Raw in packet:
                    print(f"    Payload (ICMP): {packet[Raw].load}")
                elif packet.haslayer(ICMP) and len(packet[ICMP].payload) > 0:
                    print(f"    Payload (ICMP, raw): {bytes(packet[ICMP].payload)}")
        else:
            print(f"  Other IP Protocol (Number): {packet[IP].proto}")
            # Attempt to print raw payload if available for other IP protocols
            if Raw in packet:
                print(f"    Payload (Raw): {packet[Raw].load}")
            elif len(packet[IP].payload) > 0:
                print(f"    Payload (IP, raw): {bytes(packet[IP].payload)}")
    else:
        print("  Non-IP Packet (e.g., ARP, IPv6, etc.)")
        # For non-IP packets, try to show raw payload if present
        if Raw in packet:
            print(f"  Payload (Raw): {packet[Raw].load}")
        elif len(packet) > 0:
            print(f"  Full Packet (Raw): {bytes(packet)}")


def start_sniffer(interface=None, count=0, timeout=None):
    """
    Starts the packet sniffer.

    Args:
        interface (str, optional): The network interface to sniff on (e.g., "eth0", "Wi-Fi").
                                   If None, scapy tries to find a default.
        count (int, optional): Number of packets to capture. 0 means infinite. Defaults to 0.
        timeout (int, optional): Time in seconds after which to stop sniffing. Defaults to None (no timeout).
    """
    print(f"Starting packet capture on interface: {interface if interface else 'default'}")
    print(f"Capturing {count if count > 0 else 'infinite'} packets.")
    if timeout:
        print(f"Stopping after {timeout} seconds.")
    print("Press Ctrl+C to stop the sniffer at any time.")

    try:
        # Sniff packets. prn specifies the callback function for each packet.
        # store=0 means packets are not stored in memory, which is good for continuous sniffing.
        sniff(iface=interface, prn=packet_callback, count=count, timeout=timeout, store=0)
    except PermissionError:
        print("\nERROR: Insufficient permissions. Please run the script with administrator/root privileges.")
        print("  On Linux/macOS: sudo python your_script_name.py")
        print("  On Windows: Run your command prompt/PowerShell as Administrator.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        print("\nSniffer stopped.")

# --- Main execution block ---
if __name__ == "__main__":
    # You can specify the interface here.
    # On Linux, it might be 'eth0', 'wlan0', 'lo'.
    # On macOS, it might be 'en0', 'lo0'.
    # On Windows, it might be something like 'Ethernet', 'Wi-Fi' or a GUID.
    # You can run `scapy.all.show_interfaces()` to see available interfaces.
    
    # Example: sniff on a specific interface for 10 packets
    # start_sniffer(interface="Wi-Fi", count=10)

    # Example: sniff on default interface indefinitely (Ctrl+C to stop)
    start_sniffer(count=0) # Sniffs indefinitely
    
    # Example: sniff on default interface for 30 seconds
    # start_sniffer(timeout=30)
