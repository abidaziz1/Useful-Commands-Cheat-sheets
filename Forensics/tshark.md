

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
