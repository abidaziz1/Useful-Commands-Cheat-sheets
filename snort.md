In Snort, the command parameters can be combined or separated to control various levels of detail in packet sniffing or logging. Here are some examples of Snort commands using different options:

1. **Basic verbose output**  
   ```
   snort -v
   ```
   This command runs Snort in verbose mode, showing packet summaries in real-time.

2. **Verbose with decoded output**  
   ```
   snort -vd
   ```
   Runs Snort in verbose mode and includes data-link and IP header information.

3. **Decoded output with Ethernet header**  
   ```
   snort -de
   ```
   Shows both data-link and IP headers without real-time summaries.

4. **Verbose, decoded output, and Ethernet header**  
   ```
   snort -v -d -e
   ```
   Combines verbose mode with data-link, IP, and Ethernet header information.

5. **Hex dump of packet payloads**  
   ```
   snort -X
   ```
   This shows the entire packet in hex and ASCII, which is especially useful for inspecting payload content.
   This is an excellent guide to using Snort in **Logger Mode** to log and analyze network traffic. Let’s summarize the key commands and their usage:

### 1. **Basic Logging with `-l`**
   ```bash
   sudo snort -dev -l .
   ```
   - Logs packets in the current directory.
   - Logs are saved in `tcpdump` format (binary) by default, and the log files are accessible at `/var/log/snort`.

### 2. **ASCII Logging with `-K ASCII`**
   ```bash
   sudo snort -dev -K ASCII -l .
   ```
   - Logs packets in ASCII format, categorizing them by IP address folders.
   - This format is human-readable and allows easy viewing in text editors.

### 3. **Reading Logs with `-r`**
   ```bash
   sudo snort -r snort.log.1638459842
   ```
   - Runs Snort in **packet reading mode**, reading the binary `tcpdump`-formatted log file created earlier.
   - Shows packet details similar to live sniffing mode.

### 4. **Reading with `tcpdump`**
   ```bash
   sudo tcpdump -r snort.log.1638459842 -ntc 10
   ```
   - Reads and displays the first 10 packets from the log file in `tcpdump` format.
   - Useful for reviewing logs without Snort.

### 5. **Applying Filters with `-r` and BPF**
   - Filtering packets in a log file by protocol:
     ```bash
     sudo snort -r logname.log icmp
     sudo snort -r logname.log tcp
     sudo snort -r logname.log 'udp and port 53'
     ```
   - Process only the first 10 packets:
     ```bash
     sudo snort -dvr logname.log -n 10
     ```
   - You can use **Berkeley Packet Filters (BPF)** to specify particular traffic types.


