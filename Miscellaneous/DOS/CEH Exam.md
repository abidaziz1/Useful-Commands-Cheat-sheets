### **What is a DoS Attack?**
- **Definition**: A Denial-of-Service (DoS) attack aims to disrupt, restrict, or prevent access to a computer or network's resources for legitimate users.
- **Mechanism**: Overloads a victim's system with non-legitimate requests or traffic, reducing performance or causing unavailability.
- **Goal**: Disrupt access rather than gain unauthorized access or corrupt data.

#### **Types of DoS Attacks:**
- Flooding a system or service with excess traffic or events.
- Crashing systems by sending corrupt packets or interacting with services unexpectedly.
- Consuming resources like bandwidth, CPU, or disk space.
- Causing infinite loops or other errors in system operations.

#### **Impact of DoS Attacks:**
- Resource depletion (bandwidth, CPU, memory).
- Network outages and service disruptions.
- Financial losses, operational disruptions, and loss of goodwill.
- Potential destruction of files, programs, or network components.

#### **Example Analogy**:
- Like blocking a catering company's phone lines, preventing legitimate business communication.

---
![WhatsApp Image 2024-12-19 at 10 05 17_6c633897](https://github.com/user-attachments/assets/df6b01b2-48e0-4749-810f-53f8bc34b81f)
![WhatsApp Image 2024-12-19 at 10 05 18_e1b1e370](https://github.com/user-attachments/assets/79bf009d-4c6a-4174-9afe-4180bdfed24a)

### **What is a DDoS Attack?**![WhatsApp Image 2024-12-19 at 10 16 43_f23a0eb6](https://github.com/user-attachments/assets/995c952f-c420-4a33-81bb-d8cf40b8354d)

- **Definition**: A Distributed Denial-of-Service (DDoS) attack is a large-scale, coordinated DoS attack using multiple compromised computers (botnets) to overwhelm a target system.
- **Primary Victim**: The system/service under attack.
- **Secondary Victims**: The compromised systems used to launch the attack.
![WhatsApp Image 2024-12-19 at 10 16 44_9f4a9167](https://github.com/user-attachments/assets/26c64660-bcc9-4f22-8682-1a3a4628af6f)

#### **How DDoS Works:**
1. Attackers gain control over vulnerable systems (secondary victims).
2. Install and execute DDoS software to launch a coordinated attack.
3. Flood the target system with traffic, making services unavailable to legitimate users.

#### **Why DDoS Attacks Are Popular:**
- Accessibility of exploit plans and ease of execution.
- Effectiveness in disrupting even the largest Internet hosts.

#### **Impact of DDoS Attacks**:
- Greater difficulty in tracking attackers due to distributed nature.
- Potential to render large systems

![image](https://github.com/user-attachments/assets/552b3c7f-a141-4055-8599-25f68927cb44)
![image](https://github.com/user-attachments/assets/b34e52de-e50a-4d9f-8c1a-58b198bf6e7f)
![WhatsApp Image 2024-12-19 at 10 16 44_f66ab9fd](https://github.com/user-attachments/assets/7891381f-61cd-4027-b3a1-34e8e184319b)
### **Scanning Methods for Finding Vulnerable Machines**

1. **Random Scanning**  
   - **How it works**: Infected machines probe IP addresses randomly within a target network’s range, checking for vulnerabilities.  
   - **Process**: 
     - On finding a vulnerable machine, it installs the same malicious code on it.
     - Generates significant traffic due to overlapping probes from multiple infected machines.  
   - **Speed**: Malware propagates rapidly at the beginning but slows as fewer new IP addresses remain available.  

2. **Hit-list Scanning**  
   - **How it works**:  
     - Attackers compile a list of potentially vulnerable machines (hit list).  
     - An infected machine scans the list, infects a machine, and splits the list into two.  
     - The original machine scans one half while the newly infected machine scans the other.  
   - **Result**: The number of infected machines grows exponentially.  
   - **Efficiency**: Quickly infects all machines in the hit list.

3. **Topological Scanning**  
   - **How it works**:  
     - Uses information from the infected machine, such as URLs stored on its hard drive, to locate new targets.  
     - The malware shortlists URLs and checks their vulnerability.  
   - **Accuracy**: Highly precise and effective at finding vulnerable machines connected to the infected host.  
   - **Performance**: Comparable to hit-list scanning.

4. **Local Subnet Scanning**  
   - **How it works**:  
     - Searches for vulnerable machines within the local network (behind a firewall).  
     - Exploits local addresses to find and infect machines.  
   - **Usage**: Often combined with other scanning techniques for broader infection.

5. **Permutation Scanning**  
   - **How it works**:  
     - Uses a shared pseudorandom permutation list of IP addresses, created using a block cipher and preselected key.  
     - Scanning starts from a point in the list and moves sequentially or randomly based on infection results.  
     - If the same infected machine is encountered repeatedly, scanning restarts with a new permutation key.  
   - **Advantages**:  
     - Avoids reinfecting the same targets.  
     - Ensures high scanning speed by randomly accessing new targets.  
   - **Stopping Condition**: Stops scanning when a predefined number of already infected machines are consecutively encountered.  

These methods vary in efficiency, precision, and scalability, with attackers often combining multiple techniques for maximum impact.
### **Techniques for Malicious Code Propagation**
![WhatsApp Image 2024-12-19 at 10 37 01_84446260](https://github.com/user-attachments/assets/1423e4a0-261a-46c6-84b0-81a6ed3b30ea)

1. **Central Source Propagation**  
   - **How it works**:
     - An attack toolkit is hosted on a central server (HTTP, FTP, RPC protocols).
     - When a vulnerable system is discovered, the attacker instructs the central server to transfer the toolkit to the compromised system.
     - The compromised machine automatically installs the toolkit and begins searching for other vulnerable systems, repeating the cycle.
   - **Characteristics**:
     - Centralized control.
     - High dependency on the availability of the central source.

2. **Back-chaining Propagation**  
   - **How it works**:
     - The attack toolkit resides on the attacker's system.
     - When a vulnerable system is found, the attacking machine establishes a connection (back-channel) with it.
     - The attacker transfers the toolkit to the compromised system using tools like **TFTP**, port listeners, or intruder-installed web servers.
   - **Characteristics**:
     - Direct attacker-controlled transfers.
     - Requires the attacker to maintain open communication channels with infected systems.

3. **Autonomous Propagation**  
   - **How it works**:
     - The attacking machine itself directly transfers the attack toolkit to the compromised system as soon as it gains access.
     - No reliance on external file sources or central servers.
   - **Characteristics**:
     - Self-sufficient mechanism.
     - Faster and more efficient, with no need for intermediary file storage.

**DDoS Case Study Overview**

1. **DDoS Attack Mechanism**  
   - Attackers use compromised systems (zombies) infected with Trojans to perform coordinated DoS attacks.  
   - Example: Hosting tools like High Orbit Ion Cannon (HOIC) on a server and promoting malicious download links on social media.  
   - Volunteers download the tool and execute instructions via an IRC channel, overwhelming the target server (e.g., PayPal, MasterCard).

2. **Botnet Advertising**  
   - Hackers promote botnets using blogs, search engines, social media, and fake updates.  
   - Victims download malware, spreading the botnet quickly to expand the attack network.

3. **Mobile Devices as Botnets**  
   - Android devices are primary targets due to vulnerabilities in third-party app stores.  
   - Attackers bind malware to APK files, distribute them, and take control of infected devices.  
   - Infected devices become part of botnets for DDoS attacks and other malicious activities.

4. **Google Cloud HTTP/2 ‘Rapid Reset’ Attack (September 2023)**  
   - **Scale**: Largest recorded DDoS attack at 398 million requests per second, surpassing the previous record of 46 million rps.  
   - **Mechanism**:
     - Exploited HTTP/2 stream multiplexing, sending a series of "reset" streams to disrupt servers.  
     - Targeted Google services, Google Cloud infrastructure, and customers.  
   - **Google’s Response**:
     - Utilized edge capacity and upgraded proxies to mitigate the attack.  
     - Collaborated with other providers and software maintainers to develop patches and share real-time threat intelligence.  
     - CVE-2023-44487 classified as a high-severity vulnerability with a CVSS score of 7.5.  

5. **Key Lessons from the Case Study**  
   - The HTTP/2 protocol's vulnerabilities need immediate attention.  
   - Collaborative efforts between industry peers are critical for rapid mitigation and response.  
   - Effective defense systems require robust infrastructure and real-time threat intelligence sharing.
   - ### **Basic Categories of DoS/DDoS Attack Vectors**

1. **Volumetric Attacks**  
   - **Objective**: Exhaust network bandwidth, blocking legitimate users from accessing resources.  
   - **Measurement**: Attack magnitude is measured in **bits per second (bps)**.  
   - **Mechanism**:  
     - Floods the target with massive traffic using multiple machines controlled by the attacker (botnets).  
     - Often targets stateless protocols like NTP, DNS, and SSDP, which lack congestion avoidance features.  
   - **Types**:
     - **Flood Attack**: Zombies send large volumes of traffic to exhaust the bandwidth.  
     - **Amplification Attack**: Attacker/zombies send messages to a broadcast IP, amplifying malicious traffic to consume bandwidth.  
   - **Examples of Techniques**:
     - **UDP Flood Attack**: Overwhelms the target with User Datagram Protocol packets.  
     - **ICMP Flood Attack**: Exploits Internet Control Message Protocol packets (e.g., ping requests).  
     - **Ping of Death (PoD)**: Sends oversized ping packets to crash or destabilize systems.  
     - **Smurf Attack**: Exploits ICMP to send responses to the victim from multiple sources.  
     - **Pulse Wave Attack**: Generates bursts of high-intensity traffic to overwhelm the system.  
     - **Zero-Day Attack**: Targets vulnerabilities unknown to the victim or defenders.  
     - **Malformed IP Packet Flood**: Uses corrupted IP packets to destabilize the network.  
     - **NTP Amplification Attack**: Exploits NTP servers to amplify traffic sent to the victim.  

---

2. **Protocol Attacks**  
   - **Objective**: Consume resources other than bandwidth, such as connection state tables.  
   - **Measurement**: Attack magnitude is measured in **packets per second (pps)** or **connections per second (cps)**.  
   - **Mechanism**:  
     - Exploits vulnerabilities in protocols to exhaust resources on network devices (e.g., load balancers, firewalls).  
     - Prevents new connections by keeping existing ones active indefinitely.  
   - **Examples of Techniques**:
     - **SYN Flood Attack**: Overwhelms a system with incomplete TCP connection requests.  
     - **Fragmentation Attack**: Exploits fragmented packets to exhaust resources.  
     - **Spoofed Session Flood Attack**: Fakes session data to consume resources.  
     - **ACK Flood Attack**: Bombards the system with TCP acknowledgment packets.  
     - **SYN-ACK Flood Attack**: Uses the second step of the TCP handshake to overwhelm resources.  
     - **ACK and PUSH ACK Flood Attack**: Exploits TCP flags to overload systems.  
     - **TCP Connection Flood Attack**: Creates excessive TCP connections to deplete resources.  
     - **TCP State Exhaustion Attack**: Consumes all connection state table entries.  
     - **RST Attack**: Exploits TCP reset (RST) packets to disrupt connections.  
     - **TCP SACK Panic Attack**: Leverages vulnerabilities in TCP selective acknowledgment (SACK).  
### **Application Layer Attacks**

1. **Overview**:  
   Application layer attacks target vulnerabilities in the application protocol or the application itself, aiming to prevent legitimate users from accessing the application. These attacks are less bandwidth-intensive compared to volumetric or protocol attacks and can often succeed with low traffic rates and minimal resources.

2. **Mechanism**:  
   - Attackers exploit weaknesses in unpatched, vulnerable systems to consume application resources, leaving connections open until no new connections can be made.
   - These attacks disrupt specific aspects of the application or service, such as causing temporary shutdowns or loss of services (e.g., emails, database access).
   - The attack magnitude is measured in **requests per second (rps)**.

3. **Types of Application-Level Attacks**:
   - **Buffer Overflow Attack**:  
     - The attacker sends excessive data to the application, causing it to either shut down or run malicious code.
     - This type of attack can crash vulnerable systems remotely and, in some cases, allow the attacker to execute arbitrary code on the target system.
   - **Flood Web Applications**:  
     - The attacker floods web applications with traffic that appears legitimate, overwhelming the system.
   - **Disrupt Service via Invalid Login Attempts**:  
     - Repeated invalid login attempts can block a user’s access to the system or service.
   - **Jam Database Connections with Malicious SQL Queries**:  
     - Malicious Structured Query Language (SQL) queries can be crafted to overload or disrupt the database.

4. **Challenges**:  
   - **Difficulty of Detection**:  
     - These attacks are difficult to detect as they resemble legitimate traffic once a connection is established.
   - **Low Traffic Requirement**:  
     - Only one or a few attacking machines can execute these attacks effectively, which makes them challenging to defend against.

5. **Examples of Application Layer Attack Techniques**:
   - **HTTP Flood Attack**:  
     - Floods the target web server with HTTP requests, which appear as legitimate traffic to the server.
   - **Slowloris Attack**:  
     - Keeps connections open by sending partial HTTP requests, preventing the server from closing idle connections and exhausting server resources.
   - **UDP Application Layer Flood Attack**:  
     - Sends UDP packets to the target application layer, overwhelming it with traffic.
   - **DDoS Extortion Attack**:  
     - Attackers flood the system or application while demanding a ransom to stop the attack.

### **Types of DDoS Attacks**

1. **UDP Flood Attack**
   - **Mechanism**: The attacker sends spoofed UDP packets at a high packet rate to random ports on a target server using a large source IP range.
   - **Effect**: The server repeatedly checks for nonexistent applications at the ports, consuming system resources. Legitimate applications become inaccessible, and any attempts to access them return an ICMP “Destination Unreachable” reply.
   - **Impact**: This floods the network, consuming bandwidth and resources, potentially taking the network offline.
![WhatsApp Image 2024-12-19 at 11 28 04_579dc059](https://github.com/user-attachments/assets/35aa7a1e-f7a4-4994-bed6-8bf0a2f8e44a)

2. **ICMP Flood Attack**
   - **Mechanism**: Attackers send large volumes of ICMP echo request packets (pings) directly or through reflection networks, signaling the victim’s system to reply.
   - **Effect**: The large traffic volume saturates the victim’s network bandwidth, overwhelming it and causing the system to stop responding to legitimate TCP/IP requests.
   - **Protection**: Set an ICMP flood threshold, where packets exceeding a defined rate (e.g., 1000 packets/s) trigger the rejection of further ICMP echo requests.
![WhatsApp Image 2024-12-19 at 11 28 04_e1d62376](https://github.com/user-attachments/assets/c88e7459-239c-43cb-8c6e-2ba5567860b0)

3. **Ping of Death Attack (PoD)**
   - **Mechanism**: An attacker sends malformed or oversized packets, often with sizes exceeding the maximum allowed (65,535 bytes), using a ping command.
   - **Effect**: The target system crashes or freezes during the packet reassembly process.
   - **Impact**: The attacker’s identity can be easily spoofed, and the attacker only needs the target’s IP address to initiate the attack.

4. **Smurf Attack**
   - **Mechanism**: The attacker spoofs the victim’s IP address and sends a large number of ICMP Echo request packets to a broadcast network.
   - **Effect**: All hosts on the broadcast network reply to the ICMP Echo requests, flooding the victim’s machine with responses, ultimately causing it to crash.
   - **Impact**: The victim's system is overwhelmed by traffic from the broadcasted requests.
![WhatsApp Image 2024-12-19 at 11 28 04_64285b61](https://github.com/user-attachments/assets/375ae100-0676-4bcd-b23b-74c881c48a64)

5. **Pulse Wave DDoS Attack**
   - **Mechanism**: Attackers send a repetitive strain of packets in periodic pulses to the target system every 10 minutes, with attack sessions lasting from an hour to several days.
   - **Effect**: Each pulse, often exceeding 300 Gbps, consumes the entire bandwidth of the target network.
   - **Impact**: These attacks are difficult to recover from, and can sometimes be impossible to mitigate once the attack is underway.
![WhatsApp Image 2024-12-19 at 11 28 05_eae82e65](https://github.com/user-attachments/assets/56e84ad1-43a3-499a-ab74-eea83996f9a2)

6. **Zero-Day DDoS Attack**
   - **Mechanism**: Attackers exploit DDoS vulnerabilities that have no available patches or effective defensive mechanisms.
   - **Effect**: The attacker blocks all of the victim’s resources and may steal data while the victim works to identify the vulnerability and deploy a patch.
   - **Impact**: These attacks can cause severe damage to network infrastructure and data assets until a defense mechanism is implemented. There is no widespread approach for defending against such attacks until the vulnerability is identified and patched.
### **Types of DDoS Attacks and Countermeasures**

1. **NTP Amplification Attack**  
   - **Mechanism**: The attacker uses a botnet to send spoofed UDP packets to an NTP server, triggering large response packets via the `monlist` command. The server sends these responses to the victim’s IP address, flooding it with traffic.
   - **Impact**: The victim’s network becomes congested, causing service disruption and resource exhaustion.
   - **Countermeasures**:
     - Secure NTP server configurations to prevent exploitation of the `monlist` command.
     - Limit flow control on the NTP server.
     - Monitor the network for abnormal behaviors.
     - Implement a zero-trust network approach.
     - Use firewalls to filter out malicious NTP requests.

   - **Steps to Retrieve Monlist from NTP Server**:
     - Command: `nmap -sU -pU:123 -Pn -n --script=ntp-monlist <target>`
     - Nmap will display a list of clients that have communicated with the NTP server.
![WhatsApp Image 2024-12-19 at 11 49 48_dbe3f4bf](https://github.com/user-attachments/assets/ba5a77fc-94ab-4b50-aad9-12273dd62069)

2. **SYN Flood Attack**  
   - **Mechanism**: The attacker sends numerous SYN requests to a target server with fake IP addresses. The server responds with SYN/ACK, but the attacker never completes the handshake, leaving the server waiting for the final ACK and consuming resources.
   - **Impact**: The server’s connection queue gets filled with half-open connections, exhausting its resources and preventing new legitimate connections.
   - **Countermeasures**:
     - **Packet Filtering**: Filter out invalid SYN packets.
     - **SYN Cookies**: A mechanism to prevent resource exhaustion by validating connections without allocating resources until the handshake is complete.
     - **SynAttackProtect**: A feature that helps mitigate SYN flood attacks by protecting the server's connection table.
     - **Reduce Timeout**: Decrease the time a connection is held in the “SYN RECEIVED” state to avoid filling up the queue.
     - **Disable Packet Retransmission**: Disable the retransmission of the first ACK packet in case no response is received.

3. **SYN-ACK Flood Attack**  
   - **Mechanism**: The attacker exploits the second step of the TCP three-way handshake, sending numerous SYN-ACK packets to the target, exhausting its resources.
   - **Impact**: Similar to SYN floods, this attack can overwhelm the target system by exploiting the handshake process.

4. **ACK and PUSH ACK Flood Attack**  
   - **Mechanism**: The attacker sends a large volume of spoofed ACK and PUSH ACK packets during an active TCP session, making the target system non-functional.
   - **Impact**: The system is overwhelmed, and normal communication between client and server is disrupted.

![WhatsApp Image 2024-12-19 at 11 49 48_0e716429](https://github.com/user-attachments/assets/ffbdae70-2e01-4e67-b1e5-786a6b9e2fbb)

