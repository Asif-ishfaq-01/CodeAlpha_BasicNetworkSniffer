from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DHCP,
    BOOTP,
    Raw,
    wrpcap,
    get_if_list
)
from tkinter import Tk, filedialog
from collections import Counter, defaultdict
import threading


# =========================================================
# CONFIGURATION
# =========================================================

INTERFACE = "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter"

# Payload analysis limits
MAX_PAYLOAD_SAMPLES = 10
MAX_PAYLOAD_PREVIEW = 64

# =========================================================
# TEMPORARY PACKET STORAGE
# =========================================================

captured_packets = []

# =========================================================
# GENERAL STATISTICS
# =========================================================

total_packets = 0
total_bytes = 0

protocol_counter = Counter()
application_counter = Counter()

source_ips = Counter()
destination_ips = Counter()

# =========================================================
# DHCP STATISTICS
# =========================================================

dhcp_messages = Counter()
dhcp_details = []

MAX_DHCP_DETAILS = 50

# =========================================================
# PAYLOAD STATISTICS
# =========================================================

payload_packets = 0
payload_bytes = 0

# Only store a small number of payload examples
payload_samples = []

# =========================================================
# DNS STATISTICS
# =========================================================

dns_queries = Counter()

dns_query_details = []

# =========================================================
# CONNECTION STATISTICS
# =========================================================

connections = defaultdict(
    lambda: {
        "packets": 0,
        "bytes": 0
    }
)


# =========================================================
# STOP EVENT
# =========================================================

stop_event = threading.Event()

# =========================================================
# SESSION STATE
# =========================================================

capture_running = False
capture_error = None
selected_filter = None

# =========================================================
# APPLICATION PROTOCOL IDENTIFICATION
# =========================================================

def identify_application_protocol(packet):

    # -----------------------------------------------------
    # ARP
    # -----------------------------------------------------

    if packet.haslayer(ARP):
        return "ARP"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------

    if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
        return "DHCP"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    if packet.haslayer(DNS):
        return "DNS"

    # -----------------------------------------------------
    # ICMP
    # -----------------------------------------------------

    if packet.haslayer(ICMP):
        return "ICMP"

    # -----------------------------------------------------
    # TCP
    # -----------------------------------------------------

    if packet.haslayer(TCP):

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # HTTP
        if source_port == 80 or destination_port == 80:
            return "HTTP"

        # HTTPS
        if source_port == 443 or destination_port == 443:
            return "HTTPS"

    # -----------------------------------------------------
    # UDP
    # -----------------------------------------------------

    if packet.haslayer(UDP):

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        # DNS
        if source_port == 53 or destination_port == 53:
            return "DNS"

        # QUIC / HTTP3
        if source_port == 443 or destination_port == 443:
            return "QUIC / HTTP3"

        # DHCP
        if (
            source_port in [67, 68]
            or destination_port in [67, 68]
        ):
            return "DHCP"

    return "Unknown"


# =========================================================
# PAYLOAD ANALYSIS
# =========================================================

def analyze_payload(packet):
    """
    Analyze the Raw payload of a packet.

    Returns:
        payload_length
        hexadecimal preview
        ASCII preview
    """

    # Check whether packet contains Raw data
    if not packet.haslayer(Raw):
        return 0, "", ""

    try:
        raw_data = bytes(packet[Raw].load)
    except Exception:
        return 0, "", ""

    if not raw_data:
        return 0, "", ""

    payload_length = len(raw_data)

    # Only preview the first few bytes
    preview = raw_data[:MAX_PAYLOAD_PREVIEW]

    # -----------------------------------------------------
    # HEX REPRESENTATION
    # -----------------------------------------------------

    hex_preview = " ".join(
        f"{byte:02x}"
        for byte in preview
    )

    # -----------------------------------------------------
    # ASCII REPRESENTATION
    # -----------------------------------------------------

    ascii_preview = "".join(
        chr(byte)
        if 32 <= byte <= 126
        else "."
        for byte in preview
    )

    return (
        payload_length,
        hex_preview,
        ascii_preview
    )

# =========================================================
# DNS QUERY ANALYSIS
# =========================================================

def analyze_dns(packet):

    if not packet.haslayer(DNS):
        return

    dns = packet[DNS]

    # We are interested in DNS queries
    if dns.qr != 0:
        return

    if dns.qdcount == 0:
        return

    try:

        query = dns.qd.qname.decode(
            "utf-8",
            errors="ignore"
        ).rstrip(".")

    except Exception:

        return

    # Determine DNS record type
    qtype_number = dns.qd.qtype

    dns_types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        65: "HTTPS/SVCB"
    }

    query_type = dns_types.get(
        qtype_number,
        str(qtype_number)
    )

    # Count query
    dns_queries[query] += 1

    # Store details
    if len(dns_query_details) < 50:

        source_ip = (
            packet[IP].src
            if packet.haslayer(IP)
            else "Unknown"
        )

        destination_ip = (
            packet[IP].dst
            if packet.haslayer(IP)
            else "Unknown"
        )

        dns_query_details.append(
            {
                "client": source_ip,
                "dns_server": destination_ip,
                "query": query,
                "type": query_type
            }
        )
# =========================================================
# DHCP ANALYSIS
# =========================================================

def analyze_dhcp(packet):

    if not packet.haslayer(DHCP):
        return

    try:
        options = packet[DHCP].options

        message_type = None
        hostname = None
        requested_ip = None
        server_id = None

        # -------------------------------------------------
        # Read DHCP options
        # -------------------------------------------------

        for option in options:

            if not isinstance(option, tuple):
                continue

            key = option[0]
            value = option[1]

            if key == "message-type":
                message_type = value

            elif key == "hostname":
                hostname = value

            elif key == "requested_addr":
                requested_ip = value

            elif key == "server_id":
                server_id = value

        # -------------------------------------------------
        # DHCP message names
        # -------------------------------------------------

        message_names = {
            1: "DISCOVER",
            2: "OFFER",
            3: "REQUEST",
            4: "DECLINE",
            5: "ACK",
            6: "NAK",
            7: "RELEASE",
            8: "INFORM"
        }

        message_name = message_names.get(
            message_type,
            str(message_type)
        )

        dhcp_messages[message_name] += 1

        # -------------------------------------------------
        # Client MAC address
        # -------------------------------------------------

        client_mac = "Unknown"

        if packet.haslayer(BOOTP):

            client_mac_bytes = packet[BOOTP].chaddr

            if isinstance(client_mac_bytes, bytes):

                client_mac = ":".join(
                    f"{byte:02x}"
                    for byte in client_mac_bytes[:6]
                )

        # -------------------------------------------------
        # Your assigned/requested IP
        # -------------------------------------------------

        client_ip = "Unknown"

        if packet.haslayer(BOOTP):

            yiaddr = packet[BOOTP].yiaddr

            if yiaddr:
                client_ip = yiaddr

        # -------------------------------------------------
        # Server IP
        # -------------------------------------------------

        if not server_id:
            server_id = "Unknown"

        # -------------------------------------------------
        # Store DHCP details
        # -------------------------------------------------

        if len(dhcp_details) < MAX_DHCP_DETAILS:

            dhcp_details.append({
                "message": message_name,
                "client_mac": client_mac,
                "client_ip": client_ip,
                "server_ip": server_id,
                "hostname": hostname
            })

    except Exception:
        pass

# =========================================================
# PACKET ANALYZER
# =========================================================

def analyze_packet(packet):

    global total_packets
    global total_bytes
    global payload_packets
    global payload_bytes

    # -----------------------------------------------------
    # TEMPORARILY STORE PACKET
    # -----------------------------------------------------

    captured_packets.append(packet)

    # -----------------------------------------------------
    # GENERAL STATISTICS
    # -----------------------------------------------------

    total_packets += 1
    total_bytes += len(packet)

    # -----------------------------------------------------
    # APPLICATION PROTOCOL
    # -----------------------------------------------------

    application_protocol = identify_application_protocol(packet)

    application_counter[application_protocol] += 1

    # -----------------------------------------------------
    # DNS ANALYSIS
    # -----------------------------------------------------

    analyze_dns(packet)

    # -----------------------------------------------------
    # DHCP ANALYSIS
    # -----------------------------------------------------

    analyze_dhcp(packet)

    # -----------------------------------------------------
    # PAYLOAD ANALYSIS
    # -----------------------------------------------------

    payload_length, hex_preview, ascii_preview = analyze_payload(
        packet
    )

    if payload_length > 0:

        payload_packets += 1
        payload_bytes += payload_length

        # Save only the first few examples
        if len(payload_samples) < MAX_PAYLOAD_SAMPLES:

            payload_samples.append(
                {
                    "packet_number": total_packets,
                    "application": application_protocol,
                    "payload_length": payload_length,
                    "hex": hex_preview,
                    "ascii": ascii_preview
                }
            )

    # -----------------------------------------------------
    # ARP
    # -----------------------------------------------------

    if packet.haslayer(ARP):

        protocol_counter["ARP"] += 1

        source_ips[packet[ARP].psrc] += 1
        destination_ips[packet[ARP].pdst] += 1

        return

    # -----------------------------------------------------
    # IPv4
    # -----------------------------------------------------

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        source_ips[source_ip] += 1
        destination_ips[destination_ip] += 1

        # -------------------------------------------------
        # TCP
        # -------------------------------------------------

        if packet.haslayer(TCP):

            protocol = "TCP"

            protocol_counter[protocol] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            connection = (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol
            )

            connections[connection]["packets"] += 1
            connections[connection]["bytes"] += len(packet)

        # -------------------------------------------------
        # UDP
        # -------------------------------------------------

        elif packet.haslayer(UDP):

            protocol = "UDP"

            protocol_counter[protocol] += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            connection = (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol
            )

            connections[connection]["packets"] += 1
            connections[connection]["bytes"] += len(packet)

        # -------------------------------------------------
        # ICMP
        # -------------------------------------------------

        elif packet.haslayer(ICMP):

            protocol_counter["ICMP"] += 1

        # -------------------------------------------------
        # OTHER IPv4
        # -------------------------------------------------

        else:

            protocol_counter["Other IP"] += 1

# =========================================================
# INTERFACE VALIDATION
# =========================================================
def validate_interface():

    try:

        interfaces = get_if_list()

        # Direct match
        if INTERFACE in interfaces:
            return True

        # Windows/Npcap may expose interfaces using NPF device names
        # instead of the friendly adapter name.
        if any(
            interface.startswith(r"\Device\NPF_")
            for interface in interfaces
        ):
            return True

        print()
        print("=" * 80)
        print("                 INTERFACE ERROR")
        print("=" * 80)

        print()
        print("No usable Npcap interface was detected.")

        print()
        print("Available interfaces:")

        for interface in interfaces:
            print(f"  - {interface}")

        return False

    except Exception as error:

        print()
        print("=" * 80)
        print("             INTERFACE CHECK ERROR")
        print("=" * 80)

        print()
        print(f"Error: {error}")

        return False
# =========================================================
# CAPTURE FUNCTION
# =========================================================

def start_capture(capture_filter):

    global capture_running
    global capture_error

    capture_running = True
    capture_error = None

    try:

        print()
        print("=" * 80)
        print("                    STARTING CAPTURE")
        print("=" * 80)

        print()
        print(f"Interface : {INTERFACE}")

        if capture_filter is None:
            print("Filter    : All Traffic")
        else:
            print(f"Filter    : {capture_filter}")

        print()
        print("Status    : CAPTURING")

        print()
        print("The sniffer is now capturing network traffic.")
        print("Generate traffic using your browser or ping.")
        print()
        print("Press CTRL+C to stop the capture.")
        print()
        print("-" * 80)

        # -------------------------------------------------
        # Capture loop
        # -------------------------------------------------

        while not stop_event.is_set():

            sniff(
                iface=INTERFACE,
                filter=capture_filter,
                prn=analyze_packet,
                store=False,
                timeout=1
            )

    except Exception as error:

        capture_error = error

        print()
        print("=" * 80)
        print("                    CAPTURE ERROR")
        print("=" * 80)

        print()
        print(f"Error: {error}")

        print()

    finally:

        capture_running = False

# =========================================================
# DISPLAY STATISTICS
# =========================================================

def display_statistics():

    print()
    print("=" * 80)
    print("                 NETWORK TRAFFIC SUMMARY")
    print("=" * 80)

    # =====================================================
    # GENERAL STATISTICS
    # =====================================================

    print()
    print("GENERAL STATISTICS")
    print("-" * 80)

    print(
        f"Total Packets Captured : "
        f"{total_packets}"
    )

    print(
        f"Total Bytes Captured   : "
        f"{total_bytes}"
    )

    # =====================================================
    # PROTOCOL STATISTICS
    # =====================================================

    print()
    print("PROTOCOL STATISTICS")
    print("-" * 80)

    if protocol_counter:

        for protocol, count in protocol_counter.most_common():

            if total_packets > 0:

                percentage = (
                    count / total_packets
                ) * 100

            else:

                percentage = 0

            print(
                f"{protocol:<15}"
                f"{count:>8} packets "
                f"({percentage:>6.2f}%)"
            )

    else:

        print("No protocols detected.")

    # =====================================================
    # APPLICATION PROTOCOL STATISTICS
    # =====================================================

    print()
    print("APPLICATION PROTOCOL STATISTICS")
    print("-" * 80)

    if application_counter:

        for protocol, count in application_counter.most_common():

            if total_packets > 0:

                percentage = (
                    count / total_packets
                ) * 100

            else:

                percentage = 0

            print(
                f"{protocol:<20}"
                f"{count:>8} packets "
                f"({percentage:>6.2f}%)"
            )

    else:

        print("No application protocols detected.")

    # =====================================================
    # DNS QUERY ANALYSIS
    # =====================================================

    print()
    print("DNS QUERY ANALYSIS")
    print("-" * 80)

    print(
        f"DNS Queries Detected : "
        f"{sum(dns_queries.values())}"
    )

    if dns_queries:

        print()
        print("TOP DNS QUERIES")
        print("-" * 80)

        for query, count in dns_queries.most_common(10):

            print(
                f"{query:<45}"
                f"{count:>6} queries"
            )

        print()
        print("DNS QUERY DETAILS")
        print("-" * 80)

        for item in dns_query_details:

            print(
                f"Client: {item['client']:<18}"
                f" DNS Server: {item['dns_server']:<18}"
            )

            print(
                f"Query: {item['query']:<45}"
                f" Type: {item['type']}"
            )

            print("-" * 80)

    else:

        print(
            "No DNS queries detected."
        )

    # =====================================================
    # DHCP ANALYSIS
    # =====================================================

    print()
    print("DHCP ANALYSIS")
    print("-" * 80)

    total_dhcp = sum(dhcp_messages.values())

    print(
        f"DHCP Messages Detected : {total_dhcp}"
    )

    if dhcp_messages:

        print()
        print("DHCP MESSAGE TYPES")
        print("-" * 80)

        for message, count in dhcp_messages.items():

            print(
                f"{message:<20}"
                f"{count:>6} messages"
            )

        print()
        print("DHCP MESSAGE DETAILS")
        print("-" * 80)

        for item in dhcp_details:

            print(
                f"Message    : {item['message']}"
            )

            print(
                f"Client MAC : {item['client_mac']}"
            )

            print(
                f"Client IP  : {item['client_ip']}"
            )

            print(
                f"Server IP  : {item['server_ip']}"
            )

            if item["hostname"]:

                hostname = item["hostname"]

                if isinstance(hostname, bytes):

                    hostname = hostname.decode(
                        "utf-8",
                        errors="ignore"
                    )

                print(
                    f"Hostname   : {hostname}"
                )

            print("-" * 80)

    else:

        print(
            "No DHCP messages detected."
        )

    # =====================================================
    # PAYLOAD STATISTICS
    # =====================================================

    print()
    print("PAYLOAD STATISTICS")
    print("-" * 80)

    print(
        f"Packets containing payload : "
        f"{payload_packets}"
    )

    print(
        f"Total payload bytes        : "
        f"{payload_bytes}"
    )

    if total_packets > 0:

        payload_percentage = (
            payload_packets / total_packets
        ) * 100

    else:

        payload_percentage = 0

    print(
        f"Packets with payload       : "
        f"{payload_percentage:.2f}%"
    )

    # =====================================================
    # PAYLOAD SAMPLES
    # =====================================================

    print()
    print("PAYLOAD SAMPLES")
    print("-" * 80)

    if payload_samples:

        for sample in payload_samples:

            print()
            print("=" * 70)

            print(
                f"Packet #{sample['packet_number']}"
            )

            print(
                f"Application : "
                f"{sample['application']}"
            )

            print(
                f"Payload Size: "
                f"{sample['payload_length']} bytes"
            )

            print()

            print("HEX:")
            print(
                sample["hex"]
            )

            print()

            print("ASCII:")
            print(
                sample["ascii"]
            )

    else:

        print(
            "No payload samples captured."
        )

    # =====================================================
    # TOP SOURCE IP ADDRESSES
    # =====================================================

    print()
    print("TOP SOURCE IP ADDRESSES")
    print("-" * 80)

    if source_ips:

        for ip, count in source_ips.most_common(10):

            print(
                f"{ip:<25}"
                f"{count:>8} packets"
            )

    else:

        print(
            "No source IPs detected."
        )

    # =====================================================
    # TOP DESTINATION IP ADDRESSES
    # =====================================================

    print()
    print("TOP DESTINATION IP ADDRESSES")
    print("-" * 80)

    if destination_ips:

        for ip, count in destination_ips.most_common(10):

            print(
                f"{ip:<25}"
                f"{count:>8} packets"
            )

    else:

        print(
            "No destination IPs detected."
        )

    # =====================================================
    # TOP CONNECTIONS
    # =====================================================

    print()
    print("TOP CONNECTIONS")
    print("-" * 80)

    sorted_connections = sorted(
        connections.items(),
        key=lambda item: item[1]["packets"],
        reverse=True
    )

    if sorted_connections:

        for connection, data in sorted_connections[:15]:

            (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol
            ) = connection

            print(
                f"{source_ip}:{source_port}"
                f"  →  "
                f"{destination_ip}:{destination_port}"
                f"  |  {protocol}"
                f"  |  {data['packets']} packets"
                f"  |  {data['bytes']} bytes"
            )

    else:

        print(
            "No TCP/UDP connections detected."
        )

    # =====================================================
    # END
    # =====================================================

    print()
    print("=" * 80)
    print("                  END OF SUMMARY")
    print("=" * 80)
# =========================================================
# CAPTURE FILTER SELECTION
# =========================================================

def get_capture_filter():

    print()
    print("=" * 80)
    print("                    CAPTURE FILTER")
    print("=" * 80)

    print()
    print("1. All Traffic")
    print("2. TCP Only")
    print("3. UDP Only")
    print("4. DNS Only")
    print("5. HTTP/HTTPS")
    print("6. TCP + UDP")
    print()

    while True:

        try:

            choice = input(
                "Select filter [1-6]: "
            ).strip()

        except (KeyboardInterrupt, EOFError):

            print()
            print()
            print("Filter selection cancelled.")

            return None

        filters = {
            "1": None,
            "2": "tcp",
            "3": "udp",
            "4": "udp port 53 or tcp port 53",
            "5": "tcp port 80 or tcp port 443",
            "6": "tcp or udp"
        }

        if choice in filters:

            return filters[choice]

        print()
        print("Invalid selection.")
        print("Please enter a number from 1 to 6.")
        print()

# =========================================================
# SAVE CAPTURE AS PCAP
# =========================================================

def save_capture():

    if not captured_packets:

        print()
        print("No packets were captured.")
        print("Nothing to save.")

        return

    print()
    print("=" * 80)
    print("                    SAVE CAPTURE")
    print("=" * 80)

    while True:

        choice = input(
            'Do you want to save this capture as a PCAP file? (Y/N): '
        ).strip().lower()

        if choice in ["y", "yes"]:
            break

        elif choice in ["n", "no"]:

            print()
            print("Capture was not saved.")
            print("Temporary packet data will be discarded.")

            return

        else:

            print("Invalid choice. Please enter Y or N.")

    # -----------------------------------------------------
    # OPEN WINDOWS SAVE DIALOG
    # -----------------------------------------------------

    root = Tk()

    root.withdraw()

    root.attributes("-topmost", True)

    file_path = filedialog.asksaveasfilename(
        title="Save Network Capture",
        defaultextension=".pcap",
        filetypes=[
            ("PCAP files", "*.pcap"),
            ("All files", "*.*")
        ],
        initialfile="network_capture.pcap"
    )

    root.destroy()

    # -----------------------------------------------------
    # USER CANCELLED SAVE DIALOG
    # -----------------------------------------------------

    if not file_path:

        print()
        print("Save operation cancelled.")

        return

    # -----------------------------------------------------
    # WRITE PCAP FILE
    # -----------------------------------------------------

    try:

        wrpcap(
            file_path,
            captured_packets
        )

        print()
        print("=" * 80)
        print("                  CAPTURE SAVED")
        print("=" * 80)

        print()
        print(
            f"Packets saved : {len(captured_packets)}"
        )

        print(
            f"File location : {file_path}"
        )

        print()
        print(
            "The PCAP file can now be opened in Wireshark."
        )

    except Exception as error:

        print()
        print("=" * 80)
        print("                    SAVE ERROR")
        print("=" * 80)

        print()
        print(error)

# =========================================================
# MAIN PROGRAM
# =========================================================

def main():

    global selected_filter

    print("=" * 80)
    print("                 NETWORK PACKET SNIFFER")
    print("=" * 80)

    print()
    print(f"Interface : {INTERFACE}")

    # =====================================================
    # STEP 1 — VALIDATE NETWORK INTERFACE
    # =====================================================

    print()
    print("Checking network interface...")

    if not validate_interface():

        print()
        print("Capture cannot start.")
        print("Please verify the interface name and Npcap installation.")

        return

    print("Interface validation successful.")

    # =====================================================
    # STEP 2 — SELECT CAPTURE FILTER
    # =====================================================

    selected_filter = get_capture_filter()

    # =====================================================
    # STEP 3 — START CAPTURE SESSION
    # =====================================================

    capture_thread = threading.Thread(
        target=start_capture,
        args=(selected_filter,),
        daemon=True
    )

    capture_thread.start()

    # =====================================================
    # STEP 4 — WAIT FOR CTRL+C
    # =====================================================

    try:

        while capture_thread.is_alive():

            capture_thread.join(
                timeout=0.5
            )

    except KeyboardInterrupt:

        print()
        print()

        print("=" * 80)
        print("                    STOPPING CAPTURE")
        print("=" * 80)

        print()
        print("Stopping packet capture...")

        # Signal capture thread to stop
        stop_event.set()

        # Wait for capture thread to finish
        capture_thread.join(
            timeout=3
        )

        # =================================================
        # CHECK CAPTURE THREAD STATUS
        # =================================================

        if capture_thread.is_alive():

            print()
            print(
                "Warning: Capture thread did not stop "
                "within the expected time."
            )

        else:

            print()
            print("Capture stopped successfully.")

    # =====================================================
    # HANDLE CAPTURE ERROR
    # =====================================================

    if capture_error is not None:

        print()
        print("=" * 80)
        print("             CAPTURE SESSION ERROR")
        print("=" * 80)

        print()
        print(f"Reason: {capture_error}")

        print()
        print(
            "Statistics collected before the error "
            "will still be displayed."
        )

    # =====================================================
    # DISPLAY TRAFFIC STATISTICS
    # =====================================================

    display_statistics()

    # =====================================================
    # STEP 10 — PCAP SAVE
    # =====================================================

    save_capture()

# =========================================================
# PROGRAM ENTRY POINT
# =========================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        print()
        print("Program interrupted by user.")

    except Exception as error:

        print()
        print("=" * 80)
        print("                  FATAL ERROR")
        print("=" * 80)

        print()
        print(f"Error: {error}")

        print()
        print("The program terminated safely.")

    finally:

        stop_event.set()