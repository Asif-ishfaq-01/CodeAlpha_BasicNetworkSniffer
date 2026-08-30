# Network Packet Sniffer

A Python-based network packet sniffer developed using **Scapy** for capturing, analyzing, filtering, and summarizing network traffic.

The project was developed as part of the **Code Alpha Internship** and demonstrates practical concepts of network monitoring, packet analysis, protocol identification, DNS/DHCP analysis, payload inspection, traffic filtering, and PCAP file generation.



##  Project Overview

The Network Packet Sniffer captures live network traffic from a selected network interface and analyzes packets in real time.

The tool provides information such as:

- Source and destination IP addresses
- Source and destination ports
- Network protocols
- Application protocols
- Packet and byte statistics
- DNS queries
- DHCP messages
- Payload information
- Top source IP addresses
- Top destination IP addresses
- Active network connections
- PCAP capture export

The program uses a **CLI (Command-Line Interface)** to keep the implementation lightweight and suitable for cybersecurity and networking practice.



##  Objectives

The main objectives of this project are:

1. Capture live network packets.
2. Identify common network protocols.
3. Analyze TCP, UDP, ICMP, ARP, DNS, and DHCP traffic.
4. Identify application protocols such as HTTP, HTTPS, DNS, DHCP, and QUIC/HTTP3.
5. Analyze packet payloads.
6. Provide useful traffic statistics.
7. Allow users to filter captured traffic.
8. Save captured packets as a `.pcap` file.
9. Allow saved captures to be analyzed using tools such as Wireshark.
10. Demonstrate practical network monitoring concepts using Python.


## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Scapy | Packet capture and packet analysis |
| Npcap | Windows packet capture support |
| Wireshark | PCAP analysis and verification |
| VS Code | Development environment |


##  Requirements

Before running the project, make sure the following are installed:

- Python 
- Scapy
- Npcap
- Wireshark (optional, for PCAP analysis)
- Windows operating system


##  Installation

### 1. Clone the repository
       git clone https://github.com/Asif-ishfaq-01/CodeAlpha_BasicNetworkSniffer.git

Then enter the project directory:

        cd Network_Sniffer
### 2. Create a virtual environment
        python -m venv .venv
### 3. Activate the virtual environment

        For Windows PowerShell:

            .\.venv\Scripts\Activate.ps1

    If PowerShell blocks script execution, the virtual environment can also be activated using Command Prompt:

        .venv\Scripts\activate
### 4. Install dependencies
        pip install -r requirements.txt
 
 
 ## Network Interface Configuration

        The sniffer requires a valid network interface.

        The interface name is configured in sniffer.py.

        Example:

        INTERFACE = ""YOUR_NETWORK_INTERFACE""

        The interface name may be different on another computer.

        If the configured interface is not available, the program displays the available interfaces so the user can update the configuration.

## Running the Program

    Activate the virtual environment first:
    
       .\.venv\Scripts\Activate.ps1

    Then run:

        python sniffer.py

    The program will display the network interface and provide a capture filter menu.

## Capture Filters

    The program provides the following filtering options:

        1. All Traffic
        2. TCP Only
        3. UDP Only
        4. DNS Only
        5. HTTP/HTTPS
        6. TCP + UDP
        All Traffic

    Captures all supported network traffic visible to the selected interface.

### TCP Only

    Captures TCP packets only.

### UDP Only

    Captures UDP packets only.

### DNS Only

    Captures DNS traffic using UDP and TCP port 53.

### HTTP/HTTPS

    Captures TCP traffic associated with ports 80 and 443.

### TCP + UDP

    Captures both TCP and UDP traffic.

 ## Traffic Analysis

    After stopping the capture with:

    CTRL + C

    the program generates a traffic summary.

    The summary includes:

    General Statistics
    Total packets captured
    Total bytes captured
    Protocol Statistics

    The project does not permanently store every captured packet in memory.

    PCAP File Saving

    After stopping the capture, the program provides the option to save the captured packets as a PCAP file.

    The user can:

    Stop the capture.
    Review the traffic statistics.
    Choose whether to save the capture.
    Select a save location.
    Enter a filename.
    Save the capture as a .pcap file.

    PCAP files can later be opened using Wireshark or other packet-analysis tools.

    Example:

    sample_capture.pcap
    Wireshark Compatibility

    The generated PCAP files can be opened in Wireshark for further analysis.

    This allows users to inspect:

    Individual packets
    Protocol fields
    TCP streams
    IP addresses
    Ports
    Packet timestamps
    Packet payloads
    Network conversations


## Important Limitations

    This project has several technical limitations.

1. Encrypted Traffic

        HTTPS traffic is encrypted.

        Therefore, the sniffer can identify HTTPS traffic and inspect packet metadata and encrypted payload bytes, but it cannot normally read the actual application content.

2. Network Interface Availability

        The configured network interface must exist on the system.

        Different computers may use different interface names.

3. Administrative Privileges

        Packet capture on Windows may require appropriate permissions and a properly installed/configured Npcap driver.

4. Traffic Visibility

        The sniffer can only capture traffic visible to the selected network interface.

        It does not automatically provide visibility into traffic that the operating system or network hardware does not expose to the interface.

5. Protocol Identification

        Application protocol identification is primarily based on packet layers and well-known port numbers.

        Therefore, it should not be considered a complete deep packet inspection engine.

        Ethical and Legal Notice

## This tool is intended for:

    Educational purposes

    Cybersecurity training
            
    Testing on systems and networks that you own or have explicit permission to monitor

    Do not use this tool to capture or inspect network traffic without proper authorization.

    Unauthorized packet interception may violate privacy laws, organizational policies, or other applicable regulations.



## Internship Context

    Internship: Code Alpha Internship

    Internship ID: CA/DF1/245989

    Project: Network Packet Sniffer

    The project demonstrates practical application of Python and cybersecurity concepts including packet capture, protocol analysis, network monitoring, and PCAP-based investigation.


## Author

    Muhammad Asif

    BS Information Technology Student

    Emerson University Multan (EMU)



## License

   This project was created for educational and internship purposes.
