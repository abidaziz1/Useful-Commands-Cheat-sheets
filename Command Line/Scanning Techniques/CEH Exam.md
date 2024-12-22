### Network Scanning Process

Network scanning is a comprehensive process for identifying hosts, ports, and services in a network. It enables the discovery of active devices, identification of operating systems, and system architectures of the target machines. The process helps attackers or security professionals gather IP addresses, open ports, and active services. This data helps create a detailed profile of the network and develop strategies for penetration or securing systems.

### Types of Scanning

#### Port Scanning
Port scanning involves sending messages to identify open ports and services running on the target system. This helps in identifying services that are in a "listening" state, which could be exploited. Tools probe TCP and UDP ports and reveal details such as the operating system, applications, and misconfigured services.

- Example: Open ports may allow attackers to misuse services with vulnerabilities.

#### Network Scanning
Network scanning detects active hosts and IP addresses within a network. This type of scanning is often used to map the network and locate live systems.

- Example: Ping sweeps are commonly used to identify which systems are online.

#### Vulnerability Scanning
This type of scanning involves checking systems for known vulnerabilities using predefined catalogs. It identifies exploitable weaknesses, such as outdated software, misconfigurations, or unpatched systems.

- Example: A vulnerability scanner may detect backup files or directory traversal issues.

### Objectives of Network Scanning

1. **Identify Live Hosts and Open Ports**: This helps in determining accessible systems and entry points.
2. **Determine OS and System Architecture**: Fingerprinting techniques help identify system types and vulnerabilities specific to their architecture.
3. **Discover Services and Applications**: Knowing the services running on the target allows attackers to focus on exploiting specific weaknesses.
4. **Detect Network Topology**: This involves mapping devices, routers, switches, and interconnections for a broader view of the network.
5. **Identify Specific Vulnerabilities**: Scanning tools identify misconfigurations or outdated systems that are prone to attacks.

### TCP Communication Flags

TCP communication relies on specific flags in the TCP header to manage connections. Each flag controls a specific function in the transmission process.

- **SYN**: Initiates a new connection (used in the three-way handshake).
- **ACK**: Acknowledges the receipt of a packet.
- **FIN**: Signals the termination of a connection.
- **RST**: Aborts a connection due to an error.
- **PSH**: Pushes buffered data to the receiving application.
- **URG**: Processes urgent data immediately.

#### Three-Way Handshake
The TCP handshake establishes a connection between the source and destination:
1. SYN packet from the source.
2. SYN/ACK response from the destination.
3. ACK packet from the source to confirm.
![WhatsApp Image 2024-12-22 at 13 16 54_dfe831e1](https://github.com/user-attachments/assets/91a18cfc-799e-4a6b-9dce-0c2e980ae2dd)

Connection termination involves FIN or RST packets to end communication.

### Scanning Tools

#### Nmap
Nmap is widely used for network discovery and security auditing. It identifies hosts, ports, services, and OS versions.

- Capabilities: Port scanning, OS detection, version detection, and ping sweeps.
- Syntax: `nmap <options> <Target IP>`

#### Hping3
Hping3 is a versatile network scanning tool for crafting and analyzing TCP/IP packets. It supports ICMP, TCP, UDP, and raw-IP protocols.

- **ICMP Ping**: `hping3 -1 <Target IP>` (Detect live hosts via ping requests).
- **ACK Scan**: `hping3 -A <Target IP> -p <Port>` (Check for firewalls and rule sets).
- **UDP Scan**: `hping3 -2 <Target IP> -p <Port>` (Probe UDP services).
- **SYN Flood**: `hping3 -S <Target IP> --flood` (Conduct denial-of-service attacks).
- **Port Range Scanning**: `hping3 -8 50-60 -S <Target IP>` (Scan a range of ports).

### Example Commands in Hping3

1. **ACK Scan**: `hping3 -A <Target IP> -p 80` (Probe for active firewalls).
2. **UDP Scan**: `hping3 -2 <Target IP> -p 80` (Detect services via UDP packets).
3. **SYN Scan on Ports**: `hping3 -8 50-60 -S <Target IP>` (Scan ports 50 to 60 for open connections).
4. **ICMP Ping Sweep**: `hping3 -1 10.0.1.x --rand-dest -I eth0` (Ping all devices in a subnet).

### Metasploit

Metasploit is an open-source framework designed to assist in penetration testing, security auditing, and IDS signature development. It provides tools and modules to automate discovery and exploitation processes. The framework allows the combination of exploits with various payloads, enabling flexible testing and attacking strategies. Features include open port scanning, vulnerability exploitation, network pivoting, evidence collection, and reporting.

- **Source**: [Metasploit](https://www.metasploit.com)

### NetScanTools Pro

NetScanTools Pro is a versatile network investigation tool used for troubleshooting, monitoring, and detecting devices in networks. It automates the collection of information about local LAN and Internet users, such as IP addresses, ports, domain names, and email addresses. It categorizes tools into active, passive, DNS, and local utilities, making it efficient for listing IPv4/IPv6 addresses and other network data.

- **Source**: [NetScanTools Pro](https://www.netscantools.com)

### Additional Scanning Tools

- **sx**: [GitHub](https://github.com)
- **RustScan**: [GitHub](https://github.com)
- **MegaPing**: [Magnetosoft](http://magnetosoft.com)
- **SolarWinds Engineer's Toolset**: [SolarWinds](https://www.solarwinds.com)
- **PRTG Network Monitor**: [Paessler](https://www.paessler.com)

### Host Discovery

Host discovery identifies active or "live" systems on a network. This is a primary step in scanning and helps avoid unnecessary scans of inactive systems. Techniques include ping scans, ping sweeps, and specific ping tools to determine the status of network devices.

#### Host Discovery Techniques

1. **ARP Ping Scan**: Sends ARP requests to discover devices on IPv4 networks. Active devices respond with an ARP reply, making this method highly efficient and accurate. Tools like Nmap use the `-PR` option for ARP ping scans.

2. **UDP Ping Scan**: Sends UDP packets to a target host's default port (e.g., 40,125 in Nmap). A response indicates an active host. Use the `-PU` option in Zenmap for this scan.

3. **ICMP Ping Scan**: Sends ICMP echo requests to identify live hosts. If the host is active, it returns an ICMP echo reply. Nmap uses the `-PE` option for ICMP scans.

4. **ICMP Echo Ping Sweep**: Sends ICMP echo requests to a range of IPs to discover live hosts. Tools like Nmap use the `-PE` option with a list of IPs to perform this sweep.

5. **ICMP Timestamp Ping Scan**: Queries a target for timestamp information. This technique is used for time synchronization and detecting live hosts when traditional ICMP pings are blocked. Use the `-PP` option in Zenmap.

6. **ICMP Address Mask Ping Scan**: Sends an ICMP address mask query to retrieve subnet mask information. Effective when ICMP echo requests are blocked. Use the `-PM` option in Zenmap.

7. **TCP Ping Scan**: Involves sending TCP packets (SYN or ACK) to check if the target host responds, indicating its active status.

8. **IP Protocol Scan**: Checks for the presence of specific IP protocols on the target.
![WhatsApp Image 2024-12-22 at 13 16 55_92e7e34b](https://github.com/user-attachments/assets/d69d6f26-965d-41a2-bf4e-05df0559efe5)

#### Advantages of Host Discovery Techniques

- ARP ping scans are highly accurate and efficient for discovering devices on local networks.
- UDP ping scans are useful for identifying systems behind TCP-filtering firewalls.
- ICMP ping scans are versatile for discovering active hosts and bypassing firewalls in certain configurations.
### TCP SYN Ping Scan

TCP SYN ping is a technique used for host discovery by probing specific ports to determine if they are online while avoiding connection establishment. It utilizes the three-way handshake process to confirm the target host's activity without logging traces.

- **Process**:
  1. The attacker sends a TCP SYN flag to the target host on a specified port (default: port 80).
  2. If the host is active, it replies with a SYN-ACK flag.
  3. The attacker sends an RST flag to terminate the process without establishing a full connection.

- **Advantages**:
  - Supports parallel scanning without timeouts.
  - Leaves no traces in system or network logs since no connection is established.

- **Zenmap Command**: `-PS<port(s)>`

### TCP ACK Ping Scan

TCP ACK ping scan is a variation of the SYN ping, where an empty ACK packet is sent to the target host directly to check for activity.

- **Process**:
  1. The attacker sends an ACK packet to the target (default: port 80).
  2. If the host is active, it responds with an RST packet to terminate the request.

- **Advantages**:
  - Effective in bypassing firewalls configured to block SYN packets.
  - Useful for probing firewalls and their rule sets.

- **Zenmap Command**: `-PA<port(s)>`

### IP Protocol Ping Scan

IP protocol ping sends IP packets with headers corresponding to different protocols to detect active hosts. Multiple protocols like ICMP (1), IGMP (2), and IP-in-IP (4) are used by default.

- **Process**:
  1. Probe packets with various protocol headers are sent to the target.
  2. Any response indicates that the host is online.

- **Zenmap Command**: `-PO<protocol(s)>`

### Host Discovery with AI

AI technologies can assist attackers by automating host discovery tasks. For example:

1. **Command to Perform Ping Scan**:
   ```bash
   nmap -sn 10.10.1.0/24 -OG- | awk '/Up$/{print $2}' > scan1.txt
   ```
   - Discovers live hosts and saves their IPs to a file (`scan1.txt`).

2. **Command for a Fast Comprehensive Scan**:
   ```bash
   nmap -T4 -iL scan.txt -oN scan2.txt -v0
   ```
   - Performs a fast scan on targets listed in `scan.txt` with results saved to `scan2.txt`.

3. **Command for ICMP Echo Ping Sweep**:
   ```bash
   nmap -sn -PE 10.10.1.0/24
   ```
   - Uses ICMP echo requests to identify live hosts in the range `10.10.1.0/24`.

### Ping Sweep Tools

Ping sweep tools send ICMP requests to a range of IP addresses to identify live hosts. Examples include:

- **Angry IP Scanner** ([Source](https://angryip.org)): 
  - Multithreaded scanner for IPs and ports.
  - Features include hostname resolution, MAC address detection, and saving results in various formats (CSV, TXT, XML).
  
- **Additional Tools**:
  - SolarWinds Engineer’s Toolset ([Source](https://www.solarwinds.com))
  - NetScanTools Pro ([Source](https://www.netscantools.com))
  - Colasoft Ping Tool ([Source](https://www.colasoft.com))
  - Advanced IP Scanner ([Source](https://www.advanced-ip-scanner.com))
  - OpUtils ([Source](https://www.manageengine.com))
  ### Port and Service Discovery

Port and service discovery is a crucial step in network scanning to identify open ports and the services running on live systems. It helps administrators verify security policies and attackers identify potential vulnerabilities. Misconfigured or unnecessary open ports can be exploited to compromise a system.

---

### Common Ports and Services

Below is a list of frequently used ports, protocols, and their descriptions:

| **Port/Protocol** | **Service Name**                     | **Description**                                             |
|-------------------|-------------------------------------|-----------------------------------------------------------|
| 7/tcp, udp       | echo                                | Echo service (test connectivity).                         |
| 20/tcp           | ftp-data                           | FTP data transfer.                                         |
| 21/tcp           | ftp                                 | FTP command channel.                                       |
| 22/tcp           | ssh                                 | Secure Shell (SSH).                                        |
| 23/tcp           | telnet                              | Remote login service.                                      |
| 25/tcp           | SMTP                                | Simple Mail Transfer Protocol (email service).            |
| 53/tcp, udp      | domain                              | Domain Name System (DNS).                                 |
| 80/tcp, udp      | www-http                            | Hypertext Transfer Protocol (HTTP).                       |
| 110/tcp          | pop3                                | Post Office Protocol v3 (email retrieval).                |
| 123/udp          | ntp                                 | Network Time Protocol (time synchronization).             |
| 143/tcp, udp     | imap                                | Internet Message Access Protocol (email retrieval).       |
| 443/tcp          | www-https                           | Secure HTTP (HTTPS).                                       |
| 445/tcp, udp     | microsoft-ds                        | Microsoft Directory Services.                             |
| 1433/tcp, udp    | ms-sql-s                            | Microsoft SQL Server.                                      |
| 1723/tcp, udp    | pptp                                | Point-to-Point Tunneling Protocol (VPN service).          |
| 2049/tcp, udp    | nfs                                 | Network File System.                                       |
| 5060/tcp, udp    | sip                                 | Session Initiation Protocol (VoIP services).              |
| 6667/tcp         | irc                                 | Internet Relay Chat.                                       |

---

### Port Scanning Techniques

#### 1. **TCP Connect Scan**
   - Establishes a full connection using the three-way handshake.
   - The target logs the connection, making it easier to detect.

#### 2. **TCP SYN Scan**
   - Sends a SYN packet without completing the handshake (half-open scan).
   - Less detectable since no full connection is established.

#### 3. **TCP FIN Scan**
   - Sends a FIN packet to determine the port status.
   - Works well for stealthy scans.

#### 4. **Xmas and Null Scans**
   - Sends specific flags (e.g., FIN, URG, PSH) in the Xmas scan or no flags in the Null scan.
   - Useful for bypassing firewalls.

#### 5. **UDP Scan**
   - Sends UDP packets to check for active services.
   - Less reliable due to the absence of acknowledgment in the UDP protocol.

#### 6. **Idle (Zombie) Scan**
   - Utilizes an idle host as a proxy to perform scans.
   - Highly stealthy and effective for evading detection.

#### 7. **Version Scanning**
   - Identifies the software version running on open ports.
   - Helps detect specific vulnerabilities.

#### 8. **Banner Grabbing**
   - Retrieves metadata about services running on open ports.
   - Provides information such as application name, version, and operating system.

---

### Port Scanning Tools

1. **Nmap** ([Source](https://nmap.org))
   - A versatile and powerful tool for network exploration and security auditing.
   - Capable of performing TCP, UDP, SYN, FIN, and version scans.

2. **NetScanTools Pro** ([Source](https://www.netscantools.com))
   - Offers advanced tools for port and service discovery.
   - Includes features like IP scanning, DNS tools, and SNMP analysis.

3. **Zenmap**
   - A graphical front-end for Nmap.
   - Simplifies complex scanning tasks for users.

4. **Angry IP Scanner** ([Source](https://angryip.org))
   - Scans for open ports and active hosts with a user-friendly interface.

5. **Advanced Port Scanner** ([Source](https://www.advanced-port-scanner.com))
   - Focuses on scanning open ports and detecting running services.

6. **SolarWinds Engineer’s Toolset** ([Source](https://www.solarwinds.com))
   - A comprehensive toolkit with port scanning and monitoring features.

---
### Port Scanning Techniques
![WhatsApp Image 2024-12-22 at 13 16 57_91896459](https://github.com/user-attachments/assets/cf08dd56-e0d1-4635-b28b-73c49e5a7062)
#### TCP Connect/Full-Open Scan
- **Description**: This technique uses the system's `connect()` call to establish a full connection on each target port using the TCP three-way handshake. If the port is open, the connection is successful; if closed, an error is returned.
- **Process**:
  1. The client sends a SYN packet.
  2. The target responds with a SYN/ACK if the port is open or an RST if closed.
  3. The client responds with an ACK to complete the handshake or sends an RST to terminate it after confirming the port state.
- **Advantages**:
  - Reliable and does not require superuser privileges.
- **Disadvantages**:
  - Easily detectable and logged on the target system.
- **Zenmap Command**: `-sT`
![WhatsApp Image 2024-12-22 at 13 16 57_d34fd052](https://github.com/user-attachments/assets/314493c6-92e4-42fb-8a00-a032828a1866)

---

#### Stealth Scan (Half-Open Scan)
- **Description**: This technique avoids completing the TCP three-way handshake, making it more stealthy. It sends a SYN packet and analyzes the response to determine port status, then sends an RST packet to terminate the connection.
- **Process**:
  1. The client sends a SYN packet.
  2. The target responds with a SYN/ACK if the port is open or an RST if closed.
  3. The client sends an RST to terminate the connection.
- **Advantages**:
  - Bypasses firewall rules and logging mechanisms.
- **Disadvantages**:
  - Requires superuser privileges.
- **Zenmap Command**: `-sS`

---

#### Inverse TCP Flag Scan
![WhatsApp Image 2024-12-22 at 13 16 56_ae8b3746](https://github.com/user-attachments/assets/fd188534-ded4-4b6a-83b9-c55d870b24ea)
1. **Xmas Scan**
   - **Description**: Sends a packet with FIN, URG, and PUSH flags set. No response indicates the port is open; an RST response indicates it is closed.
   - **Advantages**:
     - Effective for detecting open ports without triggering IDS.
   - **Disadvantages**:
     - Only works on UNIX-based systems (ineffective against Windows).
   - **Zenmap Command**: `-sX`
![WhatsApp Image 2024-12-22 at 13 16 56_75162cd8](https://github.com/user-attachments/assets/16ef1aa2-f72f-46fc-837f-1100ee61a29b)

2. **FIN Scan**
   - **Description**: Sends a packet with only the FIN flag set. Open ports do not respond, while closed ports send an RST.
   - **Zenmap Command**: `-sF`

3. **NULL Scan**
   - **Description**: Sends a packet with no flags set. Open ports do not respond, while closed ports send an RST.
   - **Zenmap Command**: `-sN`

4. **Maimon Scan**
   - **Description**: Similar to FIN scan but sends probe packets in a way that can sometimes bypass firewalls.
![WhatsApp Image 2024-12-22 at 13 16 57_373e6edc](https://github.com/user-attachments/assets/f77ffd6f-e743-4f2c-b9d0-0342242b7cc7)
---


#### Advantages and Disadvantages of Inverse TCP Flag Scans
- **Advantages**:
  - Avoids IDS and firewalls in many cases.
  - Stealthy and suitable for UNIX-based systems.
- **Disadvantages**:
  - Requires raw access to sockets and superuser privileges.
  - Ineffective against Windows systems.

---

#### UDP Scanning
- **Description**: Sends UDP packets to target ports. If a response is received, the port is open; if no response or ICMP unreachable error is received, it is closed or filtered.
- **Advantages**:
  - Can detect UDP services often overlooked by other scans.
- **Disadvantages**:
  - Slower than TCP scans due to no acknowledgment mechanism in UDP.

---

#### SCTP Scanning
- **INIT Scanning**:
  - Probes the initiation of SCTP associations.
- **COOKIE/ECHO Scanning**:
  - Targets systems using SCTP for verification purposes.

---

#### SSDP Scanning
- **Description**: Targets devices and services using SSDP (Simple Service Discovery Protocol), often used for IoT devices.
- **Advantages**:
  - Useful for identifying UPnP-enabled devices.

---

#### IPv6 Scanning
- **Description**: Targets systems using IPv6, probing them for open ports and services.
- **Advantages**:
  - Explores the less scrutinized IPv6 environment for vulnerabilities.

---
### ACK Flag Probe Scan

- **Description**: The ACK flag probe scan sends TCP packets with the ACK flag set and analyzes the returned RST packets' **TTL** and **WINDOW** fields to determine port status.
- **Applications**:
  - Identifies open ports by inspecting response fields.
  - Helps determine the presence of firewalls.

#### Categories of ACK Flag Probe Scans:

1. **TTL-Based ACK Flag Probe Scan**:
   - Sends multiple ACK packets to target ports.
   - Analyzes the TTL field in the returned RST packets.
   - **Open Port**: TTL < 64.
   - **Zenmap Command**: `nmap --ttl [time] [target]`.

2. **Window-Based ACK Flag Probe Scan**:
   - Sends multiple ACK packets to target ports.
   - Analyzes the **WINDOW** field in the returned RST packets.
   - **Open Port**: Non-zero window value.
   - **Zenmap Command**: `-sW`.

- **Advantages**:
  - Evades IDS in most cases.
- **Disadvantages**:
  - Effective only on systems with BSD-derived TCP/IP stacks.
  - Slow scanning process.

#### Checking Filtering Systems:
- **Stateful Firewall**: ACK packets receive no response.
- **No Firewall**: ACK packets receive an RST response.
- **Zenmap Command**: `-sA`.
![WhatsApp Image 2024-12-22 at 13 17 00_5ffb2dae](https://github.com/user-attachments/assets/0e61a4ba-ce43-4bb5-83aa-bd6bcb97821c)

---

### IDLE/IPID Header Scan

- **Description**: A spoofed scan that uses a third-party "zombie" host to identify open ports on a target.
- **Mechanism**:
  - Attacker spoofs the zombie's IP.
  - Probes the target and analyzes changes in the zombie's **IPID** values.
  - Open Port: Zombie’s IPID increases by two.
  - Closed Port: Zombie’s IPID remains unchanged.

- **Advantages**:
  - Completely stealthy.
- **Disadvantages**:
  - Requires a zombie host with predictable IPID increments.
- **Zenmap Command**: `-sI`.

---

### UDP Scanning

- **Description**: Sends UDP packets to target ports to identify open services. Open ports may not respond, while closed ports often return an ICMP "port unreachable" error.
- **Mechanism**:
  - Open Port: No response.
  - Closed Port: ICMP error received.
- **Advantages**:
  - No overhead of a TCP handshake.
  - Works efficiently on Microsoft-based OSs.
- **Disadvantages**:
  - Slower than TCP scans due to retransmissions.
  - Limited information on services.
- **Zenmap Command**: `-sU`.
![WhatsApp Image 2024-12-22 at 13 16 59_a1393fd8](https://github.com/user-attachments/assets/bb4498df-465a-4e19-9276-87b53a661a80)
---


### SCTP INIT Scan

- **Description**: A stealthy scan for SCTP (Stream Control Transmission Protocol) applications using the INIT handshake process.
- **Mechanism**:
  - Sends an INIT chunk.
  - Open Port: INIT+ACK chunk received.
  - Closed Port: ABORT chunk received.
  - Filtered Port: No response or ICMP unreachable error.
- **Advantages**:
  - Differentiates between open, closed, and filtered ports.
- **Zenmap Command**: `-sY`.
![WhatsApp Image 2024-12-22 at 13 16 59_436ac16b](https://github.com/user-attachments/assets/b6b61dd0-ad12-4559-9429-06b0ef595c34)

---

### SCTP COOKIE ECHO Scan

- **Description**: Sends COOKIE ECHO chunks to target ports and inspects responses.
- **Mechanism**:
  - Open Port: No response.
  - Closed Port: ABORT chunk received.
  - Open|Filtered: No clear differentiation.
- **Advantages**:
  - Less conspicuous than INIT scans.
- **Disadvantages**:
  - Cannot distinguish between open and filtered ports.
- **Zenmap Command**: `-sZ`.
![WhatsApp Image 2024-12-22 at 13 16 59_7e78c14e](https://github.com/user-attachments/assets/f2ac26f4-f781-4569-9e3e-03adc154ddf3)

---

### SSDP Scan

- **Description**: Simple Service Discovery Protocol (SSDP) communicates using IPv4 or IPv6 multicast addresses. It manages UPnP (Universal Plug and Play) features, responding to queries sent over broadcast addresses. Attackers exploit SSDP vulnerabilities for buffer overflow or DoS attacks.
- **Mechanism**:
  - Queries are sent using broadcast addresses.
  - Responses include UPnP feature details, aiding in vulnerability detection.
- **Tool Example**: UPnP SSDP M-SEARCH tool gleans information from UPnP-enabled systems.
- **Applications**:
  - Detecting UPnP vulnerabilities.
  - Identifying systems not protected by firewalls.

---

### List Scan

- **Description**: A non-intrusive scan that lists IPs or hostnames without actually scanning them. This method avoids any direct network interaction.
- **Mechanism**:
  - Generates a list of IPs/names based on input.
  - Performs reverse DNS resolution to fetch hostnames.
- **Zenmap Command**: `-sL`.
- **Advantages**:
  - Useful for sanity checks.
  - Detects errors in defined IPs or options files without initiating a full scan.

---

### IPv6 Scan

- **Description**: Scanning IPv6 networks is more complex than IPv4 due to the expanded address space (128 bits). Traditional ping sweeps are computationally infeasible for IPv6.
- **Challenges**:
  - Larger subnet size (2^64 host addresses).
  - Tools and techniques for IPv6 scanning are limited.
- **Mechanism**:
  - Harvest IPv6 addresses from network traffic, logs, or email headers.
  - Probe specific hosts in the subnet.
  - Multicast "all hosts" link-local address to identify sequentially numbered hosts.
- **Zenmap Command**: `-6`.
- **Applications**:
  - Identifying IPv6 hosts and open ports in a subnet.
  - Exploiting IPv6-specific vulnerabilities.

---

### Service Version Discovery

- **Description**: Determines the specific versions of services running on open ports. Attackers exploit known vulnerabilities tied to these versions.
- **Mechanism**:
  - Uses Nmap's service probes database to query services.
  - Matches responses to known patterns for version identification.
- **Zenmap Command**: `-sV`.
- **Applications**:
  - Identifying vulnerable versions of services.
  - Formulating targeted exploits.

---

### Nmap Scan Time Reduction Techniques

1. **Omit Non-Critical Tests**:
   - Avoid advanced scans (`-sC`, `-sV`, `-O`) unless necessary.
   - Use minimal scans to reduce complexity and time.

2. **Optimize Timing Parameters**:
   - Use the `-T` option to control scan aggressiveness.

3. **Separate UDP Scans**:
   - Conduct UDP scans separately due to their unique timing requirements.

4. **Upgrade Nmap**:
   - Use the latest version for better performance and bug fixes.

5. **Concurrent Scans**:
   - Split scans into smaller groups and run them in parallel.

6. **Scan from a Favorable Location**:
   - Perform scans from within the local network for faster results.

7. **Increase Bandwidth and CPU Resources**:
   - Ensure sufficient network and computational resources to improve efficiency.

---

### OS Discovery (Banner Grabbing)

#### Active Banner Grabbing
- **Description**: Sends crafted packets to the target to elicit unique responses from the TCP/IP stack.
- **Techniques**:
  - Evaluate responses to various TCP flags (e.g., SYN, ACK, URG).
  - Use ICMP and UDP packets to analyze patterns.
- **Applications**:
  - OS fingerprinting using tools like Nmap.

#### Passive Banner Grabbing
- **Description**: Observes network traffic without interacting directly with the target.
- **Techniques**:
  - Analyze error messages, network traffic, or page extensions.
  - Use sniffed packet attributes like TTL, window size, and TOS.
- **Advantages**:
  - Stealthier than active methods.
  - Effective for identifying OS and firewalls.

#### Why Banner Grabbing?
- Determines the OS and vulnerabilities of a target system.
- Helps attackers exploit specific weaknesses tied to the identified OS or service.
### Identifying Target System OS

Identifying the operating system (OS) of a target is crucial for an attacker as it allows them to tailor their attacks based on OS-specific vulnerabilities. The OS can be determined by analyzing protocol parameters such as **Time to Live (TTL)** and **TCP Window Size**, using various tools and techniques.

---

### Key Parameters for OS Identification

| **Operating System** | **TTL** | **TCP Window Size**         |
|----------------------|---------|-----------------------------|
| Linux               | 64      | 5840                        |
| FreeBSD             | 64      | 65535                       |
| OpenBSD             | 255     | 16384                       |
| Windows             | 128     | 65,535 bytes to 1 Gigabyte  |
| Cisco Routers       | 255     | 4128                        |
| Solaris             | 255     | 8760                        |
| AIX                 | 255     | 16384                       |

---

### OS Discovery Techniques

#### Using Wireshark
1. **Description**: Packet-sniffing tool that captures responses from the target machine.
2. **Method**:
   - Sniff the first TCP packet from the target.
   - Analyze the TTL and TCP Window Size fields.
   - Compare values with the OS table to infer the target OS.
3. **Tool**: [Wireshark](https://www.wireshark.org).

#### Using Nmap
1. **Description**: Versatile tool for OS discovery.
2. **Zenmap Command**: `-O` (for OS discovery).
3. **Syntax**: `nmap -O <target IP>`.
4. **Additional Features**:
   - Use `--script=smb-os-discovery` for detailed OS information via SMB protocol.

#### Using Unicornscan
1. **Description**: High-performance scanner for OS discovery.
2. **Syntax**: `unicornscan <target IP>`.
3. **Example**:
   - If TTL = 128, the target OS is likely Windows.

#### Using Nmap Script Engine (NSE)
1. **Description**: Automates OS discovery using scripts.
2. **Zenmap Command**: `-sC` (default scripts) or `--script=default`.
3. **Custom Script Example**:
   - `nmap -iL scan1.txt -O --script=default --script-args=newtargets -oN os_discovery_results.txt`.

#### Using IPv6 Fingerprinting
1. **Description**: Advanced technique for OS discovery in IPv6 networks.
2. **Mechanism**:
   - Sends probes and matches responses with a database.
   - Probes include sequence generation, ICMPv6 echo, Node Information Query, and more.
3. **Zenmap Command**: `-6 -O`.
4. **Syntax**: `nmap -6 -O <target IP>`.

---

### OS Discovery with AI

AI tools like ChatGPT can guide attackers by providing commands and scripts for automated OS discovery.

#### Example #1: Using TTL for OS Discovery
1. **Command**:
   ```bash
   ping -c 1 10.10.1.11 && echo "Check the TTL value from the response to infer the OS (Linux/Unix: 64, Windows: 128)"
   ```
2. **Explanation**:
   - Initiates a ping and checks the TTL in the response to infer the OS.

#### Example #2: Filtering TTL Value
1. **Command**:
   ```bash
   ping -c 1 10.10.1.9 | grep "ttl"
   ```
2. **Explanation**:
   - Extracts the TTL value from the ping response to determine the OS.

#### Example #3: Using Nmap Script Engine
1. **Command**:
   ```bash
   nmap -iL scan1.txt -O --script=default --script-args=newtargets -oN os_discovery_results.txt
   ```
2. **Explanation**:
   - Uses a script engine to automate OS discovery on multiple targets.

---

### Tools for OS Discovery
- **Wireshark**: Analyzes packet headers to identify OS.
- **Nmap**: Versatile for OS discovery using flags and scripts.
- **Unicornscan**: Effective for analyzing TTL values.
- **IPv6 Tools**: Handles OS detection in IPv6 environments.
### Automating Network Scanning with Custom Scripts

#### Bash Script for Network Scanning

Below is a bash script to automate network scanning tasks for a target IP range (e.g., `10.10.1.0/24`):

```bash
#!/bin/bash

# Perform a ping scan to find live hosts and save to live_hosts.txt
nmap -sP 10.10.1.0/24 -oG - | awk '/Up$/{print $2}' > live_hosts.txt

# Scan live hosts for open ports and service versions
nmap -iL live_hosts.txt -sV -oA scan_results

# Display the scan results
cat scan_results.nmap
```

#### Explanation:
1. **Discover Live Hosts**:
   - Uses `nmap -sP` for a ping scan.
   - Outputs results in greppable format (`-oG`).
   - Extracts live host IPs using `awk` and saves them to `live_hosts.txt`.

2. **Scan Live Hosts**:
   - Reads live host IPs from `live_hosts.txt`.
   - Scans for open ports and service versions (`-sV`).
   - Saves results in normal, XML, and greppable formats (`-oA`).

3. **Display Results**:
   - Outputs the results stored in `scan_results.nmap` for review.

---

### Scanning Beyond IDS and Firewalls

#### Techniques for Evasion:
1. **Packet Fragmentation**:
   - Splits probe packets into smaller fragments to bypass detection.
   - Uses tools like Nmap (`--mtu` option) for fragmentation.

2. **Source Routing**:
   - Specifies the route for packets to evade intermediate filtering.

3. **Source Port Manipulation**:
   - Sends traffic through commonly trusted ports (e.g., 80 or 443) to evade firewalls.

4. **IP Address Decoy**:
   - Spoofs multiple IP addresses to obscure the actual scanning source.

5. **IP Address Spoofing**:
   - Sends packets with a forged IP address.

6. **MAC Address Spoofing**:
   - Alters the MAC address to bypass MAC-based filters.

7. **Creating Custom Packets**:
   - Uses tools like Scapy to craft specific packet headers to evade detection.

8. **Randomizing Host Order**:
   - Randomizes the sequence of target hosts to avoid triggering IDS pattern detection.

9. **Sending Bad Checksums**:
   - Sends packets with invalid checksums, ignored by IDS but processed by some targets.

10. **Proxy Servers and Anonymizers**:
    - Routes traffic through proxies or anonymizers (e.g., Tor) to hide the attacker’s identity.

---

### Example: SYN/FIN Scanning Using IP Fragments
- **Description**:
  - Splits the TCP header into fragments to bypass packet filtering.
  - Reassembled packets may trigger vulnerabilities in the target system.

- **Advantages**:
  - Evades detection by signature-based IDS.
  - Exploits improper handling of fragmented packets.

- **Potential Effects**:
  - Crashes or abnormal behavior on the target system.

---

### Automating Scanning with AI

#### Example Prompt:
"Develop a script to automate network scanning for live systems, open ports, and services in the target IP range 10.10.1.0/24."

#### Script:
```bash
#!/bin/bash

# Ping sweep to find live systems
nmap -sP 10.10.1.0/24 -oG - | awk '/Up$/{print $2}' > live_hosts.txt

# Detailed scan for live hosts
nmap -iL live_hosts.txt -sV -O --script=default -oA detailed_scan

# Output results
echo "Detailed scan results saved to detailed_scan.*"
```
### Techniques for Bypassing IDS and Firewalls

#### 1. **Source Routing**
   - **Description**: Manipulates the IP options field in a packet to enforce a specific route that bypasses firewalls or IDS-configured routers.
   - **Mechanism**:
     - Attackers dictate the packet path by using loose or strict source routing.
     - This avoids routers configured to block malicious traffic.
   - **Use Case**:
     - Avoiding security mechanisms between the attacker and target.

---

#### 2. **Source Port Manipulation**
   - **Description**: Alters source port numbers to use trusted ports (e.g., HTTP, DNS) and bypass firewall rules.
   - **Mechanism**:
     - Sends packets with a spoofed source port, such as port 80, to pass through firewalls.
   - **Example**:
     - Zenmap command: `nmap -g 80 [target]`
   - **Use Case**:
     - Evading firewalls configured to allow traffic only from specific ports.

---

#### 3. **IP Address Decoy**
   - **Description**: Uses decoy IP addresses to confuse IDS and firewalls, making it difficult to identify the real scanning source.
   - **Types of Decoy Scans**:
     1. **Random Decoys**:
        ```bash
        nmap -D RND:10 [target]
        ```
        - Generates 10 random decoy IPs.
     2. **Manual Decoys**:
        ```bash
        nmap -D decoy1,decoy2,decoy3,ME,... [target]
        ```
        - Allows manual specification of decoy IPs.
   - **Use Case**:
     - Obfuscating the attacker’s real IP address.

---

#### 4. **IP Address Spoofing**
   - **Description**: Modifies the source IP in a packet header to masquerade as another system.
   - **Mechanism**:
     - Victim responds to the spoofed address instead of the attacker's real IP.
   - **Example**:
     - Using Hping3:
       ```bash
       hping3 www.certifiedhacker.com -a 7.7.7.7
       ```
   - **Use Case**:
     - Performing DoS attacks or bypassing IP-based filters.

---

#### 5. **MAC Address Spoofing**
   - **Description**: Alters the source MAC address to bypass MAC-based firewalls.
   - **Mechanism**:
     - Replaces the actual MAC address with a spoofed one.
   - **Example**:
     - Using Nmap:
       ```bash
       nmap -sT -Pn --spoof-mac 0 [Target IP]
       ```
       - Randomizes the MAC address.
       ```bash
       nmap -sT -Pn --spoof-mac [Vendor] [Target IP]
       ```
       - Spoofs MAC based on vendor.
   - **Use Case**:
     - Evading MAC address filtering in networks.

---

#### 6. **Creating Custom Packets**
   - **Description**: Uses packet crafting tools to generate custom TCP/IP packets for bypassing firewalls and IDS.
   - **Tools**:
     - **Colasoft Packet Builder**:
       - Allows editing packet headers and crafting fragmented packets.
     - **NetScanTools Pro**:
       - Builds custom packets and audits networks.
   - **Use Case**:
     - Bypassing security mechanisms using crafted packets.

---

#### 7. **Randomizing Host Order**
   - **Description**: Scans target hosts in a random sequence to avoid detection by IDS.
   - **Example**:
     - Nmap command: `--randomize-hosts`.
   - **Use Case**:
     - Avoiding detection in monitored networks.

---

#### 8. **Sending Bad Checksums**
   - **Description**: Sends packets with invalid TCP/UDP checksums to test firewall configurations.
   - **Mechanism**:
     - Properly configured systems drop the packets.
     - Misconfigured systems respond, revealing weaknesses.
   - **Example**:
     - Nmap command: `--badsum`.
   - **Use Case**:
     - Identifying improperly configured firewalls or IDS.

---

### Practical Examples Using Nmap

#### Source Port Manipulation
```bash
nmap -g 80 [target]
```
- Scans target using port 80 as the source port to bypass firewalls.

#### Decoy Scanning
1. **Random Decoys**:
   ```bash
   nmap -D RND:10 [target]
   ```
2. **Manual Decoys**:
   ```bash
   nmap -D 192.168.1.1,192.168.1.2,ME,192.168.1.3 [target]
   ```

#### MAC Address Spoofing
1. **Random MAC Address**:
   ```bash
   nmap -sT -Pn --spoof-mac 0 [Target IP]
   ```
2. **Vendor-Specific MAC**:
   ```bash
   nmap -sT -Pn --spoof-mac [Vendor] [Target IP]
   ```

#### Custom Packet Creation
Using **Colasoft Packet Builder**:
1. Edit TCP parameters in the **Decode Editor** or **Hex Editor**.
2. Send crafted packets to bypass IDS/firewalls.

#### Bad Checksum Scanning
```bash
nmap --badsum [target]
```

These techniques demonstrate how attackers evade IDS/firewalls and perform scans to gather network information stealthily.
### Proxy Servers and Anonymization Techniques

#### **Proxy Servers**
- **Definition**: Intermediaries between a client and the Internet, used for anonymization, access control, and bandwidth optimization.

##### **Uses of Proxy Servers**:
- **Firewall Protection**: Shields local networks from external attacks.
- **IP Multiplexing**: Enables multiple devices to share a single IP (NAT/PAT).
- **Anonymization**: Masks user IPs for private browsing.
- **Content Filtering**: Blocks ads or unsuitable material.
- **Bandwidth Optimization**: Reduces data consumption.

##### **How Proxy Servers Work**:
- Proxy servers handle requests from clients and forward them to destination servers, transmitting responses back to the client.

##### **Why Attackers Use Proxy Servers**:
- **Hide Identity**: Conceal IP addresses to avoid detection.
- **Access Blocked Content**: Bypass restrictions or firewalls.
- **Disguise Scans**: Mask scanning activities as legitimate traffic.
- **Chaining**: Use multiple proxies for enhanced anonymity.

---

#### **Proxy Tools**
1. **Proxy Switcher** ([proxyswitcher.com](https://www.proxyswitcher.com)):
   - Allows anonymous browsing and bypassing restrictions.
2. **CyberGhost VPN** ([cyberghostvpn.com](https://www.cyberghostvpn.com)):
   - Encrypts connections, hides IPs, and prevents tracking.
3. **Additional Tools**:
   - **Burp Suite** ([portswigger.net](https://www.portswigger.net))
   - **Tor** ([torproject.org](https://www.torproject.org))
   - **Proxifier** ([proxifier.com](https://www.proxifier.com))

---

#### **Anonymizers**
- **Definition**: Intermediate servers that mask user identities and enable anonymous browsing.

##### **Types of Anonymizers**:
1. **Networked Anonymizers**:
   - Pass data through multiple nodes for enhanced privacy.
   - **Advantage**: Complex communication paths make tracking difficult.
   - **Disadvantage**: Increased risk of data exposure at each node.
2. **Single-Point Anonymizers**:
   - Relay data through a single intermediary server.
   - **Advantage**: Simple and effective for basic anonymity.
   - **Disadvantage**: Susceptible to advanced traffic analysis.

##### **Tools**:
1. **Whonix** ([whonix.org](https://www.whonix.org)):
   - Debian-based OS focused on security and anonymity.
2. **Psiphon** ([psiphon.ca](https://psiphon.ca)):
   - Circumvents censorship using SSH and VPN tunnels.
3. **TunnelBear** ([tunnelbear.com](https://www.tunnelbear.com)):
   - Provides encrypted access to restricted websites.
4. **I2P (Invisible Internet Project)** ([geti2p.net](https://geti2p.net)):
   - Peer-to-peer proxy network for anonymous browsing.

---

#### **Censorship Circumvention Tools**
1. **AstrillVPN** ([astrill.com](https://www.astrill.com)):
   - Bypasses geo-restrictions and Internet censorship while encrypting traffic.
2. **Tails** ([tails.net](https://tails.net)):
   - A live OS for anonymous Internet use and secure file encryption.

---

### Advanced Techniques

#### **Proxy Chaining**
- **Process**:
  1. User request passes through multiple proxy servers.
  2. Each proxy strips identification before passing the request further.
- **Result**: Enhanced anonymity by obscuring the origin of traffic.
- **Example**:
  ```bash
  nmap -D 192.168.1.1,192.168.1.2,192.168.1.3,ME 10.10.1.11
  ```

#### **MAC Address Spoofing**
- **Description**: Alters MAC addresses to bypass filtering systems.
- **Command**:
  ```bash
  nmap -sT -Pn --spoof-mac 0 [Target IP]
  ```
  - Randomizes MAC addresses during scans.

#### **Randomizing Host Order**
- **Description**: Randomizes the scanning sequence to evade detection.
- **Command**:
  ```bash
  nmap --randomize-hosts
  ```

### Network Scanning Countermeasures

#### **Ping Sweep Countermeasures**
- **Firewall Configuration**: Block incoming ICMP echo requests from unknown or untrusted sources.
- **IDS/IPS Utilization**: Use systems like Snort to detect and prevent ping sweeps.
- **Evaluate ICMP Traffic**: Monitor and restrict unnecessary ICMP traffic in the network.
- **Connection Termination**: Disconnect hosts sending excessive ICMP echo requests (e.g., more than 10 requests).
- **DMZ Setup**: Allow only essential ICMP commands (e.g., ECHO_REPLY, HOST_UNREACHABLE, TIME_EXCEEDED) in the DMZ.
- **Rate Limiting**: Limit ICMP packet rates to hinder ping sweeps.
- **Network Segmentation**: Divide the network into smaller isolated segments to limit attacker discovery scope.
- **Private IP Addressing and NAT**: Use private IP ranges and implement NAT to hide internal IPs.

---

#### **Port Scanning Countermeasures**
- **Firewall and IDS/IPS Rules**:
  - Detect and block probes from port-scanning tools.
  - Analyze packet data rather than just headers.
- **Regular Testing**: Run port scanning tools internally to assess firewall effectiveness.
- **System and Firmware Updates**: Ensure all devices have updated firmware and software.
- **Minimize Open Ports**: Keep only necessary ports open, and filter others.
- **Block Unnecessary Services**: Stop services on ports that are not in use.
- **Restrict ICMP Traffic**: Block inbound ICMP messages and ICMP type-3 unreachable messages at border routers.
- **Routing and Source Protection**: Block source routing and spoofing techniques at firewalls and routers.
- **Honeypots and Empty Hosts**: Redirect scans to honeypots or empty hosts to mislead attackers.
- **Advanced Techniques**:
  - Implement port knocking to hide open ports.
  - Use NAT and VLANs for IP obfuscation and traffic segmentation.
  - Employ egress filtering to control outbound traffic.
  - Use TCP wrappers for domain or IP-based access control.

---

#### **Banner Grabbing Countermeasures**
- **Disabling or Modifying Banners**:
  - Disable unnecessary services that reveal sensitive information.
  - Use server masking tools to modify banner data.
  - Hide server details by editing configuration files (e.g., `httpd.conf` for Apache, `UrlScan.ini` for Windows servers).
- **HTTP Header Adjustments**:
  - Remove headers like `X-Powered-By` and replace or disable HTTP methods (`Connect`, `Put`, `Delete`, `Options`).
  - Set secure headers in `web.config` or equivalent files.
- **Hiding File Extensions**:
  - Mask or eliminate file extensions to obscure server technology.
  - Use application mappings or directives (e.g., Apache's `mod_negotiation`).
- **Packet Filtering**:
  - Block or restrict access to ports exposing banners.
  - Use secure protocols like HTTPS, SFTP/FTPS, and SSH to encrypt banner information.
- **Encryption**: Apply TLS for services to protect banner data during connection handshakes.

---

### IP Spoofing Detection Techniques

#### **1. Direct TTL Probes**
- **Description**: Send a ping request to the legitimate host and observe the TTL value in the reply. Compare it with the TTL of the packet under inspection.
- **Steps**:
  1. Check if the TTL values match; they should be the same if the packets use the same protocol.
  2. For mismatched TTLs, calculate the actual hop count: subtract the reply TTL value from the initial TTL value.
  3. If the TTL or hop count does not align, the packet may be spoofed.
- **Limitations**: May produce false negatives if the attacker knows the hop count between the source and host.

---

#### **2. IP Identification Number**
- **Description**: Monitor the incremental IPID value in IP packet headers.
- **Steps**:
  1. Send a probe packet to the source IP address of the suspicious packet.
  2. Observe the IPID in the reply packet.
  3. If the IPID value is not close to or slightly greater than that of the probe packet, the packet is likely spoofed.
- **Effectiveness**: Works well even if the attacker and target are on the same subnet.

---

#### **3. TCP Flow Control Method**
- **Description**: Use the sliding window principle of TCP to control and analyze packet flow.
- **Steps**:
  1. Observe if packets are sent after the recipient's window size is exhausted.
  2. Spoofed packets often disregard window size constraints.
  3. During a TCP handshake, set SYN-ACK to zero. A legitimate client will respond with only an ACK packet, while a spoofed sender may send additional data.
- **Advantages**: Effective in detecting spoofed packets during the handshake process.

---

### IP Spoofing Countermeasures

#### **1. Avoid Trust Relationships**
- Eliminate reliance on IP-based authentication.
- Use password-based or multifactor authentication alongside trust relationships.

---

#### **2. Use Firewalls and Filtering Mechanisms**
- **Inbound Filtering**: Block incoming packets with spoofed source IPs using access-control lists (ACLs).
- **Outbound Filtering**: Inspect outgoing traffic to prevent sensitive data leakage.
- **Additional Measures**: Update firewall firmware and monitor for unusual traffic patterns.

---

#### **3. Use Random Initial Sequence Numbers (ISNs)**
- Prevent attackers from predicting ISNs by employing random number generation for ISN assignment.

---

#### **4. Ingress and Egress Filtering**
- **Ingress Filtering**: Prevent spoofed traffic from entering the network by dropping packets with out-of-range source addresses.
- **Egress Filtering**: Block outgoing packets with incorrect source addresses to prevent spoofing.

---

#### **5. Use Encryption**
- Apply strong encryption like IPSec for data authentication, integrity, and confidentiality.
- Use VPNs to secure communications and make spoofing attacks harder to execute.

---

#### **6. SYN Flooding Countermeasures**
- Deploy SYN cookies or RST cookies to mitigate SYN flooding, which often accompanies spoofing attacks.

---

#### **7. Other Measures**
- **IPv6 Migration**: Transition to IPv6 for enhanced security.
- **Digital Certificates**: Use domain and two-way authentication certificates.
- **Dynamic Addressing**: Implement random IPv6 address variation to reduce vulnerability windows.
- **Network Address Translation (NAT)**: Conceal internal network addresses.
- **Secure Protocols**: Use HTTPS, SFTP, SSH, and other encrypted protocols.
- **Advanced Tools**: Employ mitigation devices like Behemoth scrubbers for deep packet inspection.

---

### Scanning Detection and Prevention Tools

1. **ExtraHop**:
   - Provides real-time detection and response to malicious network scanning.
   - Analyzes all network interactions, including SSL/TLS traffic.

2. **Additional Tools**:
   - Splunk Enterprise Security: Comprehensive log analysis and threat detection.
   - Scanlogd: Detects scanning attempts by monitoring network traffic.
   - Vectra Detect: Uses AI to identify malicious behavior in network traffic.
   - IBM Security QRadar XDR: Offers extended threat detection and response.
   - Cynet 360 AutoXDR™: Automated threat detection and remediation. 
![WhatsApp Image 2024-12-22 at 13 16 59_18bd24e0](https://github.com/user-attachments/assets/f7daa0a4-7946-4369-bd23-1a1d80c539f1)
![WhatsApp Image 2024-12-22 at 13 16 59_4d6fe61b](https://github.com/user-attachments/assets/8407c3aa-c253-4f08-81ea-4a6eadb45ffe)
![WhatsApp Image 2024-12-22 at 13 17 00_3f5c12ad](https://github.com/user-attachments/assets/f8914157-1388-4e51-a621-d59ddc7bd6e6)
![WhatsApp Image 2024-12-22 at 13 17 00_985778f9](https://github.com/user-attachments/assets/85e588cd-fbee-416e-bb18-d1c18533bbb8)

![WhatsApp Image 2024-12-22 at 13 17 00_db2a9bad](https://github.com/user-attachments/assets/ae40d724-0aaf-4246-b7ee-682ce4c7073d)






