

### **1. Basic Capture Commands**

- **Capture All Traffic on All Interfaces**:
  ```bash
  tcpdump -i any
  ```

- **Capture Traffic on a Specific Interface (e.g., eth0)**:
  ```bash
  tcpdump -i eth0
  ```

- **Capture and Display a Set Number of Packets**:
  ```bash
  tcpdump -i eth0 -c 50
  ```

- **Capture and Save Output to a File**:
  ```bash
  tcpdump -i eth0 -w capture.pcap
  ```

- **Read Packets from a Saved Capture File**:
  ```bash
  tcpdump -r capture.pcap
  ```

---

### **2. Filtering by Protocols**

- **Capture Only TCP Traffic**:
  ```bash
  tcpdump -i eth0 tcp
  ```

- **Capture Only UDP Traffic**:
  ```bash
  tcpdump -i eth0 udp
  ```

- **Capture Only ICMP Traffic (Ping Requests)**:
  ```bash
  tcpdump -i eth0 icmp
  ```

---

### **3. Filtering by Ports**

- **Capture Traffic on a Specific Port (e.g., HTTP on port 80)**:
  ```bash
  tcpdump -i eth0 port 80
  ```

- **Capture Traffic on Multiple Ports (e.g., 80 and 443)**:
  ```bash
  tcpdump -i eth0 port 80 or port 443
  ```

- **Capture Traffic Within a Range of Ports**:
  ```bash
  tcpdump -i eth0 portrange 1000-2000
  ```

---

### **4. Filtering by IP Address**

- **Capture Traffic to/from a Specific IP**:
  ```bash
  tcpdump -i eth0 host 192.168.1.10
  ```

- **Capture Traffic to a Specific IP**:
  ```bash
  tcpdump -i eth0 dst 192.168.1.10
  ```

- **Capture Traffic from a Specific IP**:
  ```bash
  tcpdump -i eth0 src 192.168.1.10
  ```

- **Exclude Traffic from a Specific IP**:
  ```bash
  tcpdump -i eth0 not host 192.168.1.10
  ```

---

### **5. Filtering by TCP Flags**

- **Capture Only SYN Packets (Connection Initiation)**:
  ```bash
  tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'
  ```

- **Capture SYN-ACK Packets (Connection Acknowledgement)**:
  ```bash
  tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
  ```

- **Capture Only FIN Packets (Connection Termination)**:
  ```bash
  tcpdump -i eth0 'tcp[tcpflags] & tcp-fin != 0'
  ```

- **Capture Only RST Packets (Connection Reset)**:
  ```bash
  tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'
  ```

---

### **6. Filtering by Packet Size**

- **Capture Packets Larger Than a Specific Size (e.g., 1000 Bytes)**:
  ```bash
  tcpdump -i eth0 greater 1000
  ```

- **Capture Packets Smaller Than a Specific Size**:
  ```bash
  tcpdump -i eth0 less 1000
  ```

---

### **7. Display Options**

- **Display Output in Hexadecimal and ASCII**:
  ```bash
  tcpdump -i eth0 -X
  ```

- **Display Only Brief Packet Information**:
  ```bash
  tcpdump -i eth0 -q
  ```

- **Include Ethernet Headers (MAC Addresses)**:
  ```bash
  tcpdump -i eth0 -e
  ```

- **Disable Name Resolution for Faster Capture**:
  ```bash
  tcpdump -i eth0 -n
  ```

- **Disable Both Name and Port Resolution**:
  ```bash
  tcpdump -i eth0 -nn
  ```

---

### **8. Advanced Filtering**

- **Capture All Traffic Except on Port 22**:
  ```bash
  tcpdump -i eth0 not port 22
  ```

- **Capture Only Outgoing Traffic**:
  ```bash
  tcpdump -i eth0 outbound
  ```

- **Capture Only Incoming Traffic**:
  ```bash
  tcpdump -i eth0 inbound
  ```

- **Capture Fragmented Packets**:
  ```bash
  tcpdump -i eth0 'ip[6:2] & 0x1fff != 0'
  ```

---

### **9. Useful Capture Examples**

- **Capture DNS Traffic (UDP Port 53)**:
  ```bash
  tcpdump -i eth0 udp port 53
  ```

- **Capture HTTPS Traffic to/from a Specific Host**:
  ```bash
  tcpdump -i eth0 host example.com and port 443
  ```

- **Capture and Show Only Packets with SYN or ACK Flags Set**:
  ```bash
  tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
  ```

---

### **10. Additional Options**

- **Set Snap Length to Limit Capture Size per Packet**:
  ```bash
  tcpdump -i eth0 -s 100
  ```

- **Capture for a Specific Duration (e.g., 10 Seconds)**:
  ```bash
  timeout 10 tcpdump -i eth0
  ```

- **Save Capture and Print Output Simultaneously**:
  ```bash
  tcpdump -i eth0 -w capture.pcap | tee tcpdump.log
  ```
