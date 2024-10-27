# System Resource Usage Monitor (SRUM)

The SRUM is a Windows feature that tracks the last 30 to 60 days of resource usage, such as:

Application and service activity
Network activity, such as packets sent and received
User activity (I.e. launching services or processes).
In a database (SRUDB.dat) on the host, this can be found at ```C:\Windows\System32\sru\SRUDB.dat```

# Windows Firewall Logs

Before proceeding, check if logging is enabled. By default, Windows Firewall will log to ```C:\Windows\System32\LogFiles\Firewall.```


---

### 1. **Show TCP Connections and Associated Processes**
   - **Command**: `Get-NetTCPConnection`
   - **Purpose**: Lists TCP connections along with details about associated processes, IP addresses, and ports. This can help identify unusual or suspicious connections.
   - **Usage Example**:
     ```powershell
     Get-NetTCPConnection | select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{Name="Cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} | sort RemoteAddress -Descending | ft -wrap -autosize
     ```
   - **Sample Output**: Shows local and remote addresses, ports, connection states, process names, and command line execution paths.

### 2. **Show UDP Connections**
   - **Command**: `Get-NetUDPEndpoint`
   - **Purpose**: Lists active UDP connections. UDP connections are useful to monitor because some malicious activity (like botnets) use UDP for communication.
   - **Usage Example**:
     ```powershell
     Get-NetUDPEndpoint | select LocalAddress, LocalPort, CreationTime, Remote*
     ```
   - **Sample Output**: Displays the local addresses and ports in use for UDP connections, along with timestamps. No remote address is shown as UDP doesn’t establish a dedicated connection.

### 3. **Sort and Unique Remote IPs**
   - **Command**: `(Get-NetTCPConnection).RemoteAddress | Sort-Object -Unique`
   - **Purpose**: Lists all unique remote IPs involved in active TCP connections. Useful for identifying external IPs interacting with the system.
   - **Usage Example**:
     ```powershell
     (Get-NetTCPConnection).RemoteAddress | Sort-Object -Unique
     ```
   - **Sample Output**: Provides a unique list of IPs, which can then be cross-referenced with threat intelligence.

### 4. **Investigate a Specific IP Address**
   - **Command**: `Get-NetTCPConnection -RemoteAddress <IP>`
   - **Purpose**: Displays details about connections to a specific IP address, including state, connection initiation time, and port details.
   - **Usage Example**:
     ```powershell
     Get-NetTCPConnection -RemoteAddress 51.15.43.212 | select State, CreationTime, LocalPort, RemotePort
     ```
   - **Sample Output**: Information about the connection status, times, and local/remote ports, which can help pinpoint specific suspicious activity.

### 5. **Retrieve DNS Cache**
   - **Command**: `Get-DnsClientCache`
   - **Purpose**: Shows recent DNS entries the host has resolved. This cache can reveal recently accessed domains, indicating network activity and potential indicators of compromise.
   - **Usage Example**:
     ```powershell
     Get-DnsClientCache | ? Entry -NotMatch "workst|servst|memes|kerb|ws|ocsp"
     ```
   - **Sample Output**: Lists recently resolved DNS names, filtering out common system services. This can reveal new or suspicious domains the system has recently communicated with.

### 6. **View Hosts File**
   - **Command**: `gc -tail 4 "C:\Windows\System32\Drivers\etc\hosts"`
   - **Purpose**: Displays the last few lines of the `hosts` file. The hosts file overrides DNS, and attackers can modify it to redirect legitimate traffic to malicious servers.
   - **Usage Example**:
     ```powershell
     gc -tail 4 "C:\Windows\System32\Drivers\etc\hosts"
     ```
   - **Sample Output**: Shows entries in the hosts file, where IPs map to specific domains. Suspicious entries here could indicate unauthorized redirects.

### 7. **Querying WinRM (Windows Remote Management) Sessions**
   - **Command**: `Get-WSManInstance -ResourceURI winrm/config/Listener`
   - **Purpose**: Shows active WinRM sessions. WinRM is often used by administrators but can be abused by attackers to remotely control the system.
   - **Usage Example**:
     ```powershell
     Get-WSManInstance -ResourceURI winrm/config/Listener
     ```
   - **Sample Output**: Details of active WinRM sessions, which may reveal unauthorized remote control or persistence mechanisms.

### 8. **Querying RDP Logs**
   - **Command**: `qwinsta`
   - **Purpose**: Lists active and recent Remote Desktop Protocol (RDP) connections. RDP sessions can indicate who has been remotely accessing the machine.
   - **Usage Example**:
     ```powershell
     qwinsta
     ```
   - **Sample Output**: Displays session names, usernames, IDs, states, and types of RDP connections, showing recent logins or attempts to connect via RDP.

### 9. **Querying SMB (Server Message Block) Shares**
   - **Command**: `Get-SmbConnection`
   - **Purpose**: Shows established SMB connections. SMB is commonly used for file sharing in Windows networks and can indicate both legitimate and malicious connections.
   - **Usage Example**:
     ```powershell
     Get-SmbConnection
     ```
   - **Sample Output**: Displays details of SMB connections, including server names, share names, and usernames. These can help identify unauthorized file sharing or data exfiltration.

---

These PowerShell commands are effective for quickly identifying potential network anomalies and system activity, especially useful for incident response and system triage when traditional tools are unavailable. They provide insights into network connections, DNS resolutions, active remote sessions, and shared resources that may indicate signs of compromise or unauthorized access.


Here’s a detailed summary of the `Packet Monitor (Pktmon)` and `Netstat` commands for capturing and analyzing network activity on a Windows machine:

---

### Packet Monitor (Pktmon)

**Pktmon** is a built-in Windows packet sniffing tool available in Windows 10, Windows Server 2019, and Server 2022. It operates on the network stack and is useful for capturing network data directly on the machine.

#### Key Commands and Their Descriptions:
- **`pktmon start`**: Begins a packet capture. Running `pktmon start -c` enables a circular logging mode with a default file size of 512 MB.
- **`pktmon stop`**: Stops the packet capture session.
- **`pktmon reset`**: Resets the packet capture count, useful for starting fresh without accumulated old data.
- **`pktmon counters`**: Shows the number of packets captured across interfaces.
- **`pktmon etl2txt`**: Converts the `.etl` file generated by Pktmon to a human-readable `.txt` file.
- **`pktmon etl2pcap`**: Converts the `.etl` capture file to a `.pcap` file, which can then be analyzed in tools like Wireshark.

#### Example Usage:
To start a capture:
```powershell
pktmon start -c
```

To stop a capture:
```powershell
pktmon stop
```

To view capture counters:
```powershell
pktmon counters
```

To convert the capture file to a `.pcap` format:
```powershell
pktmon etl2pcap -i C:\Windows\system32\PktMon.etl -o C:\Users\Administrator\Documents\PktMon.pcap
```

---

### Netstat

**Netstat** is a built-in Windows utility that displays active TCP/UDP connections and various other network-related information. It’s useful for quickly viewing network activity and diagnosing connections, especially in triaging and network troubleshooting scenarios.

#### Key Commands and Their Descriptions:
- **`netstat -a`**: Displays all active TCP connections and the state of TCP/UDP ports.
- **`netstat -b`**: Shows the executable responsible for each connection (e.g., `svchost.exe`).
- **`netstat -o`**: Displays TCP connections along with the associated Process ID (PID).
- **`netstat -p <protocol>`**: Filters connections by protocol (e.g., TCP, UDP). For example, `netstat -p tcp` lists only TCP connections.

These options can be combined for more detailed output. For example:
```powershell
netstat -a -b
```
This command shows all active TCP connections along with the associated executable.

#### Example Usages:
1. **Display all active connections with executables**:
   ```powershell
   netstat -a -b
   ```

2. **Display all active connections with PIDs**:

   ```powershell
   netstat -a -o
   ```

3. **Export Netstat Output**:
   Use redirection to export Netstat output to a file, which is helpful for analyzing or sharing logs:
   ```powershell
   netstat -a -o > C:\Users\Administrator\Documents\netstat_output.txt
   ```

---
![screencapture-medium-embossdotar-tryhackme-windows-network-analysis-writeup-92f6278e27ae-2024-10-27-12_34_18](https://github.com/user-attachments/assets/92d23159-0d67-46fa-b8a3-5851a44cd105)
