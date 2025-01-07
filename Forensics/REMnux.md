
---
### **REMnux Advanced Malware Analysis Cheat Sheet**

---

#### **1. General REMnux Setup**
- **Update REMnux**: Always start by ensuring REMnux is updated with the latest tools.
  ```bash
  sudo remnux upgrade
  ```

- **Useful Directories**:
  - `/home/ubuntu/Desktop/tasks/`: Location where task files (such as evidence) are stored.
  - `/var/log/inetsim/`: INetSim log directory.
  - `/opt/remnux/`: Common location for REMnux-installed tools.

#### **2. Static Analysis Tools**
- **oledump.py** - Analyzes OLE2 (Compound File Binary Format) files.
  ```bash
  oledump.py file.doc
  # Extract specific stream (e.g., stream 4) with VBA decompression
  oledump.py file.doc -s 4 --vbadecompress
  ```

- **pdfid.py & peepdf** - Analyze PDF files for malicious content.
  ```bash
  pdfid.py file.pdf        # Summarize potential exploit indicators in a PDF
  peepdf file.pdf          # Advanced PDF analysis with an interactive shell
  ```

- **exiftool** - Extracts metadata from files, useful for hidden data.
  ```bash
  exiftool file.docx
  ```

- **YARA** - Search for signatures or IOCs (Indicators of Compromise) within files.
  ```bash
  yara -r rule.yara file.exe   # Recursively scan with YARA rules
  ```

#### **3. Dynamic Analysis Tools**

- **INetSim** - Simulate network services to observe malware behavior in a controlled environment.
  - **Configure INetSim**:
    ```bash
    sudo nano /etc/inetsim/inetsim.conf
    # Set dns_default_ip to your REMnux VM IP (e.g., 10.10.102.171)
    dns_default_ip 10.10.102.171
    ```
  - **Start INetSim**:
    ```bash
    sudo inetsim
    ```
  - **Common INetSim Logs**:
    - `/var/log/inetsim/` - Check HTTP, HTTPS, and DNS logs for connections.

- **Wireshark / tcpdump** - Capture and analyze network traffic.
  ```bash
  sudo tcpdump -i eth0 -w capture.pcap
  wireshark capture.pcap
  ```

- **FakeNet-NG** - Alternative to INetSim for simulating network responses.
  ```bash
  sudo fakenet
  ```

#### **4. Memory Forensics with Volatility**
- **Load Memory Image**:
  ```bash
  vol3 -f memory.mem [plugin]
  ```

- **Common Volatility Plugins**:
  - **Process Tree**: Display process hierarchy.
    ```bash
    vol3 -f memory.mem windows.pstree.PsTree
    ```
  - **DLL List**: Lists DLLs loaded in each process.
    ```bash
    vol3 -f memory.mem windows.dlllist.DllList
    ```
  - **Malfind**: Detect injected code (e.g., DLL injection).
    ```bash
    vol3 -f memory.mem windows.malfind.Malfind
    ```
  - **CmdLine**: List command-line arguments for processes.
    ```bash
    vol3 -f memory.mem windows.cmdline.CmdLine
    ```

- **Automate Plugin Execution**:
  ```bash
  for plugin in windows.malfind.Malfind windows.psscan.PsScan; do vol3 -q -f memory.mem $plugin > memory.$plugin.txt; done
  ```

#### **5. Advanced File Analysis**
- **Strings Analysis**:
  ```bash
  strings -a file.exe > file.strings.txt           # Extract ASCII strings
  strings -e l file.exe > file.unicode_little.txt  # Extract little-endian Unicode
  strings -e b file.exe > file.unicode_big.txt     # Extract big-endian Unicode
  ```

- **Detect Obfuscation**:
  - Use **CyberChef** (included in REMnux or online) for deobfuscating strings, performing XOR, Base64 decoding, etc.

- **radare2 / r2** - Advanced binary analysis with an interactive shell.
  ```bash
  r2 -A file.exe
  aaa                    # Analyze all symbols and functions
  pdf @ main             # Print disassembly of 'main'
  ```

#### **6. Browser Emulation & URL Analysis**
- **curl** - Test URLs in a controlled environment.
  ```bash
  curl -v -A "Mozilla/5.0" "http://malicious-url.com"
  ```

- **wget** - Download files from simulated URLs without SSL verification.
  ```bash
  wget --no-check-certificate http://10.10.102.171/malware.zip
  ```

- **URLQuery & VT-Zilla Plugins** - Integrate URL analysis with **VirusTotal** and **URLQuery** plugins to identify potentially malicious URLs.

#### **7. Advanced Network Emulation**
- **Custom DNS Responses with INetSim** - Simulate DNS responses by modifying `/etc/inetsim/inetsim.conf`.
  ```bash
  dns_default_ip 10.10.102.171
  ```
  Restart INetSim after changes:
  ```bash
  sudo inetsim restart
  ```

- **Response Emulation**: Use FakeNet-NG configuration files to specify custom responses per protocol (HTTP, HTTPS, FTP).

#### **8. Automating Malware Analysis Workflow**
- **Create a Script for Automation**:
  - You can combine various tools for an automated analysis pipeline. Example script:

    ```bash
    #!/bin/bash
    # Set variables
    file="$1"
    output_dir="analysis_output"
    mkdir -p "$output_dir"
    
    # Run static analysis tools
    exiftool "$file" > "$output_dir/exiftool_output.txt"
    strings "$file" > "$output_dir/strings_output.txt"
    yara -r rules.yara "$file" > "$output_dir/yara_output.txt"
    
    # Run Volatility plugins if analyzing memory
    if [[ "$file" == *.mem ]]; then
      for plugin in windows.malfind.Malfind windows.psscan.PsScan; do
        vol3 -q -f "$file" $plugin > "$output_dir/${file##*/}.$plugin.txt"
      done
    fi
    
    echo "Analysis completed. Results saved in $output_dir."
    ```

- **Cron Jobs for Scheduled Analysis**: Use `cron` to run daily scans on new files or evidence directories.
  ```bash
  crontab -e
  # Add job (e.g., run every day at midnight)
  0 0 * * * /path/to/analysis_script.sh
  ```

#### **9. Tips for Handling Encrypted or Packed Malware**
- **Unpacking and Decrypting**:
  - **upx** - Unpack UPX-packed binaries.
    ```bash
    upx -d packed_file.exe
    ```
  - **Uncompyle6** - Decompile Python bytecode.
    ```bash
    uncompyle6 -o output_dir compiled.pyc
    ```

- **Obfuscation Tools**:
  - Use **CyberChef** for rapid decoding, especially with **XOR** or **Base64**-encoded payloads.
  - **radare2** or **Ghidra** for reverse engineering obfuscated code in binaries.

#### **10. Forensic Logging and Reporting**
- **Maintaining Logs**:
  - Ensure all INetSim logs are intact for tracking malware network behaviors.
  - Capture console output from analysis sessions and save to a log file:
    ```bash
    script analysis.log
    # Run analysis commands here
    exit
    ```

- **Report Generation**:
  - Export findings to a structured report, including screenshots and command output summaries.
  - Consider automated report generation using Markdown or tools like **Jupyter Notebooks** for an interactive, shareable format.

---

### **Quick Commands Reference**

| Task                         | Command/Tool                                       |
|------------------------------|----------------------------------------------------|
| Update REMnux                | `sudo remnux upgrade`                              |
| OLE File Analysis            | `oledump.py file.doc -s [stream] --vbadecompress`  |
| PDF Analysis                 | `pdfid.py file.pdf`                                |
| Static YARA Scan             | `yara -r rules.yara file.exe`                      |
| Start INetSim                 | `sudo inetsim`                                    |
| Capture Network Traffic      | `sudo tcpdump -i eth0 -w capture.pcap`             |
| Strings Extraction           | `strings file.exe > strings_output.txt`            |
| Run Volatility Plugins       | `vol3 -f memory.mem [plugin]`                      |
| Auto-Run Volatility          | `for plugin in ...; do vol3 ...; done`             |
| Unpack UPX                   | `upx -d packed_file.exe`                           |
| Analyze URL                  | `curl -v -A "Mozilla/5.0" "http://url.com"`        |

---

