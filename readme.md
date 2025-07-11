# **CodeAlpha\_NetworkSniffer**

This repository contains the solution for **Task 1: Basic Network Sniffer** as part of the **CodeAlpha Cyber Security Internship Program**.

## **Project Overview**

This Python program is a basic network packet sniffer designed to capture and analyze network traffic. It provides insights into the structure and content of data packets, demonstrating fundamental concepts of network communication and protocols.

## **Features**

* **Packet Capture:** Utilizes the scapy library to intercept network packets in real-time.  
* **Packet Analysis:** Parses captured packets to extract and display key information.  
* **Detailed Information Display:** For each packet, the program displays:  
  * Source and Destination MAC Addresses (Ethernet Layer)  
  * Source and Destination IP Addresses (IP Layer)  
  * Network Protocol (e.g., TCP, UDP, ICMP)  
  * Source and Destination Ports (for TCP/UDP)  
  * TCP Flags (for TCP packets)  
  * ICMP Type and Code (for ICMP packets)  
  * Raw Payload content (where available)

## **Technologies Used**

* **Python 3.x**  
* **Scapy library:** A powerful interactive packet manipulation program.

## **How to Run**

1. **Clone the repository:**  
   git clone https://github.com/YourGitHubUsername/CodeAlpha\_NetworkSniffer.git  
   cd CodeAlpha\_NetworkSniffer

2. **Install Dependencies:**  
   pip install scapy

3. **Install Npcap (Windows Only):**  
   * Download and install [Npcap](https://nmap.org/npcap/) (ensure "Install Npcap in WinPcap API-compatible Mode" is checked during installation).  
   * Restart your computer after installation.  
4. **Run the script (with Administrator/Root privileges):**  
   * **On Linux/macOS:**  
     sudo python packet\_analyzer.py

   * **On Windows:** Open Command Prompt or PowerShell **as Administrator**, then navigate to the project directory and run:  
     python packet\_analyzer.py

5. **Observe Traffic:** The program will start capturing and displaying network packets. Generate some network activity (e.g., browse a website, ping an IP) to see the output. Press Ctrl+C to stop the sniffer.

## **Learning Outcomes**

This project helped in understanding:

* The basics of network packet structure.  
* How data flows through different layers of the network.  
* The fundamental concepts of common network protocols (IP, TCP, UDP, ICMP).  
* Practical application of the scapy library for network analysis.

**Note:** This project was completed as part of the CodeAlpha Cyber Security Internship program.