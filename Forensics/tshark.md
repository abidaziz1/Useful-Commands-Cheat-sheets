

---

## **General Commands**

| Command                    | Description                                                                            | Example                                 |
|----------------------------|----------------------------------------------------------------------------------------|-----------------------------------------|
| `tshark -h`                | Display help page with common features.                                                | `tshark -h`                             |
| `tshark -v`                | Show TShark version information.                                                       | `tshark -v`                             |
| `tshark -D`                | List available interfaces for capturing.                                               | `tshark -D`                             |
| `tshark -i <interface>`    | Specify interface to capture on (by number or name).                                   | `tshark -i 1` or `tshark -i eth0`       |
| `sudo tshark`              | Start live capturing with root privileges (required for sniffing live traffic).        | `sudo tshark`                           |

---

## **File Operations (Reading/Writing)**

| Command                    | Description                                                                            | Example                                 |
|----------------------------|----------------------------------------------------------------------------------------|-----------------------------------------|
| `tshark -r <file.pcap>`    | Read packets from a capture file.                                                      | `tshark -r capture.pcap`                |
| `tshark -w <file.pcap>`    | Write captured packets to a specified file.                                            | `tshark -w output.pcap`                 |
| `tshark -r <file> -w <out>`| Read from a file and write filtered results to another file.                           | `tshark -r capture.pcap -Y "http" -w http-filtered.pcap` |

---

## **Capture Conditions and Limits**

| Command                         | Description                                                                                      | Example                                        |
|---------------------------------|--------------------------------------------------------------------------------------------------|------------------------------------------------|
| `tshark -c <count>`             | Stop capturing after capturing specified number of packets.                                      | `tshark -c 100`                                |
| `tshark -a duration:<seconds>`  | Stop capture after specified time in seconds.                                                    | `tshark -a duration:60`                        |
| `tshark -a filesize:<KB>`       | Stop capture when file reaches specified size in KB.                                            | `tshark -a filesize:1024`                      |
| `tshark -a files:<number>`      | Set the maximum number of capture files; when reached, oldest files will be overwritten.         | `tshark -w buffer-output.pcap -a filesize:1024 -a files:5` |

### **Ring Buffer Options**

| Command                             | Description                                                                                      | Example                                                   |
|-------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `tshark -b duration:<seconds>`      | Create new file after specified duration.                                                        | `tshark -w ring-buffer.pcap -b duration:60`               |
| `tshark -b filesize:<KB>`           | Create new file when file reaches specified size.                                                | `tshark -w ring-buffer.pcap -b filesize:1024`             |
| `tshark -b files:<number>`          | Overwrite oldest file in ring buffer after specified number of files.                            | `tshark -w ring-buffer.pcap -b filesize:1024 -b files:3`  |

---

## **Display and Verbosity Options**

| Command                    | Description                                                                            | Example                                 |
|----------------------------|----------------------------------------------------------------------------------------|-----------------------------------------|
| `tshark -q`                | Silent mode (suppresses live output).                                                  | `tshark -q`                             |
| `tshark -V`                | Verbose mode to show detailed packet information.                                      | `tshark -r capture.pcap -V`             |
| `tshark -x`                | Display packet bytes in hex and ASCII format.                                          | `tshark -r capture.pcap -x`             |
| `tshark -T fields -e <field>`| Extract specific fields and display only the chosen data field.                      | `tshark -T fields -e ip.src -e ip.dst`  |

---

## **Capture Filters (Set Before Capture)**

| Command                                | Description                                                                                     | Example                                 |
|----------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------|
| `-f "<filter>"`                        | Apply BPF syntax capture filter to limit captured data (live only).                              | `tshark -f "port 80"`                   |
| `host <IP>`                            | Capture traffic to/from a specific IP address.                                                  | `tshark -f "host 192.168.1.1"`          |
| `net <IP/CIDR>`                        | Capture traffic within a network.                                                               | `tshark -f "net 192.168.0.0/24"`        |
| `port <port>`                          | Capture traffic on a specific port.                                                             | `tshark -f "port 443"`                  |
| `src` or `dst`                         | Filter source or destination addresses.                                                         | `tshark -f "src host 192.168.1.1"`      |
| `tcp`, `udp`, `icmp`                   | Capture only specific protocol traffic.                                                         | `tshark -f "tcp"`                       |
| `tshark -f "<expression>"`             | Combine filters with logical operators (e.g., `&&`, `||`).                                      | `tshark -f "tcp port 80 && host 10.0.0.1"` |

---

## **Display Filters (Post-Capture Filtering)**

| Command                                | Description                                                                                     | Example                                 |
|----------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------|
| `-Y "<filter>"`                        | Apply display filter to view specific packets post-capture.                                     | `tshark -Y "http"`                      |
| `ip.addr == <IP>`                      | Display packets with specific IP address.                                                       | `tshark -Y "ip.addr == 192.168.1.1"`    |
| `ip.src` / `ip.dst`                    | Display packets from/to a specific IP.                                                          | `tshark -Y "ip.src == 192.168.1.1"`     |
| `tcp.port == <port>`                   | Display packets with specific TCP port.                                                         | `tshark -Y "tcp.port == 80"`            |
| `http.request`                         | Display only HTTP requests.                                                                     | `tshark -Y "http.request"`              |
| `dns`                                  | Display only DNS packets.                                                                       | `tshark -Y "dns"`                       |
| `http.response.code == <code>`         | Display HTTP packets with specific response code.                                               | `tshark -Y "http.response.code == 200"` |
| `icmp`                                 | Display ICMP packets.                                                                           | `tshark -Y "icmp"`                      |

---

## **Field Extraction and Formatting**

| Command                                | Description                                                                                     | Example                                 |
|----------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------|
| `tshark -T fields -e <field>`          | Extract specific fields (e.g., IP addresses, ports).                                            | `tshark -T fields -e ip.src -e ip.dst`  |
| `-E separator=<char>`                  | Set field separator for extracted data.                                                         | `tshark -T fields -e ip.src -E separator=,` |
| `-E quote=d`                           | Wrap extracted field values in double quotes.                                                   | `tshark -T fields -e ip.src -E quote=d` |
| `-T json`                              | Output in JSON format.                                                                          | `tshark -T json -e frame.number -e ip.src` |
| `-T pdml`                              | Output in PDML (XML-based) format.                                                              | `tshark -T pdml`                        |

---

## **Examples of Complex Usage**

### Capture Traffic on Port 80, Save to File, Stop After 60 Seconds
```bash
tshark -f "port 80" -w web_traffic.pcap -a duration:60
```

### Read Packets from File, Show Only HTTP Packets with Status Code 200
```bash
tshark -r capture.pcap -Y "http.response.code == 200"
```

### Extract Only IP Source and Destination from a Capture File, Display in CSV Format
```bash
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -E separator=,
```

### Capture on Interface `eth0`, Filter for DNS Traffic, Display in JSON Format
```bash
tshark -i eth0 -f "port 53" -T json -e frame.number -e dns.qry.name
```

### Capture HTTP Traffic for Specific IP, Limit to 100 Packets, Verbose Output
```bash
tshark -i eth0 -f "host 192.168.1.1 and port 80" -c 100 -V
```

### Set Autostop Parameters to Capture Traffic for 5 Files, Each 1MB, 2s Duration per File
```bash
tshark -w traffic_capture.pcap -a filesize:1024 -a files:5 -a duration:2
```

### Display All Packets with TCP FIN Flag Set
```bash
tshark -Y "tcp.flags.fin == 1"
```

### Use Display Filter to

 Show Only HTTPS Traffic with TLS Protocol
```bash
tshark -Y "tls and tcp.port == 443"
```


---

## **Extended TShark Commands for Protocol-Specific Filtering**

These commands focus on extracting HTTP URIs, FTP commands, SMTP details, and other frequently analyzed protocol data.

### **HTTP Protocol Analysis**

| Command                                          | Description                                                                                      | Example                                                 |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `tshark -r <file> -Y 'http.request.full_uri'`    | Display full URIs of HTTP requests.                                                              | `tshark -r capture.pcap -Y 'http.request.full_uri'`     |
| `tshark -r <file> -Y 'http.request.method'`      | Display only HTTP request methods (GET, POST, etc.).                                             | `tshark -r capture.pcap -Y 'http.request.method'`       |
| `tshark -r <file> -Y 'http.response.code == 200'`| Filter for HTTP responses with a status code of 200 (OK).                                        | `tshark -r capture.pcap -Y 'http.response.code == 200'` |
| `tshark -r <file> -Y 'http.host'`                | Extract HTTP host headers to see which domains were contacted.                                   | `tshark -r capture.pcap -Y 'http.host'`                 |

### **DNS Protocol Analysis**

| Command                                      | Description                                                                                      | Example                                                |
|----------------------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `tshark -r <file> -Y 'dns'`                  | Display only DNS traffic.                                                                        | `tshark -r capture.pcap -Y 'dns'`                      |
| `tshark -r <file> -Y 'dns.qry.name'`         | Display DNS query names to see which domains were requested.                                     | `tshark -r capture.pcap -Y 'dns.qry.name'`             |
| `tshark -r <file> -Y 'dns.a'`                | Display resolved IP addresses from DNS responses.                                                | `tshark -r capture.pcap -Y 'dns.a'`                    |
| `tshark -r <file> -Y 'dns.qry.type == 1'`    | Display only DNS "A" (Address) records.                                                          | `tshark -r capture.pcap -Y 'dns.qry.type == 1'`        |

### **FTP Protocol Analysis**

| Command                                          | Description                                                                                      | Example                                                 |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `tshark -r <file> -Y 'ftp'`                      | Display only FTP traffic.                                                                        | `tshark -r capture.pcap -Y 'ftp'`                       |
| `tshark -r <file> -Y 'ftp.request.command'`      | Display FTP request commands (e.g., USER, PASS, LIST).                                           | `tshark -r capture.pcap -Y 'ftp.request.command'`       |
| `tshark -r <file> -Y 'ftp.response.arg'`         | Display arguments in FTP responses.                                                              | `tshark -r capture.pcap -Y 'ftp.response.arg'`          |

### **SMTP Protocol Analysis**

| Command                                          | Description                                                                                      | Example                                                 |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `tshark -r <file> -Y 'smtp'`                     | Display only SMTP traffic.                                                                       | `tshark -r capture.pcap -Y 'smtp'`                      |
| `tshark -r <file> -Y 'smtp.req.parameter'`       | Extract SMTP request parameters, useful for analyzing email headers or commands.                 | `tshark -r capture.pcap -Y 'smtp.req.parameter'`        |
| `tshark -r <file> -Y 'smtp.rcpt_to'`             | Display the recipient addresses in SMTP (e.g., RCPT TO).                                         | `tshark -r capture.pcap -Y 'smtp.rcpt_to'`              |

### **ICMP Protocol Analysis**

| Command                                  | Description                                                                                      | Example                                                |
|------------------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `tshark -r <file> -Y 'icmp'`             | Display only ICMP traffic.                                                                       | `tshark -r capture.pcap -Y 'icmp'`                     |
| `tshark -r <file> -Y 'icmp.type == 8'`   | Display only ICMP Echo (ping) requests.                                                          | `tshark -r capture.pcap -Y 'icmp.type == 8'`           |
| `tshark -r <file> -Y 'icmp.code == 0'`   | Filter by specific ICMP code, useful for identifying ICMP message types.                         | `tshark -r capture.pcap -Y 'icmp.code == 0'`           |

### **General Field Extraction**

| Command                                      | Description                                                                                      | Example                                                |
|----------------------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `tshark -r <file> -T fields -e <field>`      | Extract specific fields (e.g., `http.host`, `ip.src`).                                           | `tshark -r capture.pcap -T fields -e ip.src -e ip.dst` |
| `tshark -r <file> -Y <filter> -T fields -e <field>` | Apply filter, then extract fields.                                                                | `tshark -r capture.pcap -Y 'http' -T fields -e http.host` |

Here’s a structured TShark command-line cheat sheet in table format, covering basic, intermediate, and advanced commands with examples and combinations to make it easy for quick reference.

---

| **Feature**                     | **Command** & **Example**                                                                                                       | **Description**                                                                                      |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| **Basic Read & Display**        | `tshark -r file.pcap`                                                                                                           | Reads a `.pcap` file in TShark.                                                                      |
| **Display Filter**              | `tshark -r file.pcap -Y 'http'`                                                                                                 | Filters packets to show only HTTP traffic.                                                           |
| **Extract Specific Fields**     | `tshark -r file.pcap -T fields -e ip.src -e ip.dst -E header=y`                                                                 | Extracts source and destination IP addresses with headers.                                           |

---

### **Statistics and Protocol Hierarchy**

| **Feature**                      | **Command** & **Example**                                                                                                        | **Description**                                                                                     |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Protocol Hierarchy**           | `tshark -r file.pcap -z io,phs -q`                                                                                               | Displays a summary of protocols in the capture.                                                     |
| **Packet Length Distribution**    | `tshark -r file.pcap -z plen,tree -q`                                                                                            | Shows distribution of packet sizes.                                                                 |
| **Endpoint Statistics**          | `tshark -r file.pcap -z endpoints,ip -q`                                                                                         | Lists all endpoints by IP address.                                                                  |
| **Conversation Statistics**      | `tshark -r file.pcap -z conv,ip -q`                                                                                              | Shows conversation stats between IPs (e.g., byte counts, frame counts).                             |

---

### **Advanced Filtering: Contains & Matches**

| **Feature**                      | **Command** & **Example**                                                                                                        | **Description**                                                                                     |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Contains Filter (case-sensitive)** | `tshark -r file.pcap -Y 'http.server contains "Apache"'`                                                                      | Filters for packets where `http.server` contains "Apache".                                          |
| **Matches Filter (regex)**       | `tshark -r file.pcap -Y 'http.request.method matches "(GET|POST)"'`                                                              | Filters HTTP packets where request method matches "GET" or "POST".                                  |

---

### **Stream Analysis**

| **Feature**                      | **Command** & **Example**                                                                                                        | **Description**                                                                                     |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Follow TCP Stream**            | `tshark -r file.pcap -z follow,tcp,ascii,0 -q`                                                                                   | Follows the TCP stream of the 0th session in ASCII format.                                          |
| **Follow HTTP Stream**           | `tshark -r file.pcap -z follow,http,ascii,1 -q`                                                                                  | Follows the 1st HTTP stream in ASCII format.                                                        |

---

### **Extracting Information for Investigation**

| **Feature**                  | **Command** & **Example**                                                                                                         | **Description**                                                                                       |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| **Extract Hostnames (DHCP)** | `tshark -r file.pcap -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r`                   | Extracts DHCP hostnames, sorts, and shows counts of unique values.                                     |
| **Extract DNS Queries**      | `tshark -r file.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r`                                                       | Extracts DNS query names, sorts, and displays counts for each unique query.                             |
| **Extract User Agents**      | `tshark -r file.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r`                                                      | Extracts and counts HTTP user agents to help identify client types or tool signatures.                  |

---

### **Exporting Objects & Detecting Credentials**

| **Feature**                    | **Command** & **Example**                                                                                                         | **Description**                                                                                       |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| **Export HTTP Objects**        | `tshark -r file.pcap --export-objects http,<target_folder> -q`                                                                   | Extracts HTTP objects/files from the capture to a specified folder.                                   |
| **Detect Cleartext Credentials** | `tshark -r file.pcap -z credentials -q`                                                                                         | Finds cleartext credentials in protocols like FTP, HTTP, IMAP, POP, and SMTP.                         |

---

### **Combined Commands for Workflow Efficiency**

| **Task**                               | **Combined Command**                                                                                                        | **Description**                                                                                     |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Extract and Count DNS Queries**      | `tshark -r file.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r`                                                      | Extracts and organizes DNS queries to identify frequently accessed domains.                           |
| **Extract and Sort HTTP User Agents**  | `tshark -r file.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r`                                                      | Lists unique user agents and shows counts, helpful for identifying patterns in browser or bot traffic. |
| **Follow TCP Stream and Filter Output**| `tshark -r file.pcap -z follow,tcp,ascii,0 -q | grep "<pattern>"`                                                              | Follows a TCP stream, filters for specific patterns, allowing focused stream analysis.               |

---
