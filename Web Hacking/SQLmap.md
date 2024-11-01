---

### **Basic Command Structure**
```bash
sqlmap -u <URL> [options]
```

### **Setup and Basics**
- `-u "<URL>"`: Specifies the target URL for SQL injection testing.
- `--data="<POST data>"`: Use this for POST requests; e.g., `--data="username=admin&password=1234"`.
- `--cookie="<cookie string>"`: Adds cookies for sessions or authenticated scans.
- `--level=[1-5]`: Sets the level of tests (default is 1; higher levels add more tests).
- `--risk=[1-3]`: Sets the risk level (default is 1; higher risks may try more intrusive tests).

### **Detection Flags**
- `--batch`: Runs SQLMap without prompts, using default responses.
- `--random-agent`: Randomizes the User-Agent to avoid detection.
- `--tor`: Routes traffic through the TOR network for anonymity.
- `--wizard`: Launches an interactive setup guide (recommended for beginners).
  
### **Testing Injection Points**
- `--technique=<techniques>`: Limits testing to specified SQL injection types (B, E, U, S, T):
  - `B`: Boolean-based blind
  - `E`: Error-based
  - `U`: UNION query-based
  - `S`: Stacked queries
  - `T`: Time-based blind
  ```bash
  sqlmap -u <URL> --technique=BEUS
  ```
  
### **Database Enumeration**
- `--dbs`: Lists all available databases.
  ```bash
  sqlmap -u <URL> --dbs
  ```
- `-D <database_name> --tables`: Lists all tables in a specific database.
  ```bash
  sqlmap -u <URL> -D users --tables
  ```
- `-D <database_name> -T <table_name> --columns`: Lists all columns in a specific table.
  ```bash
  sqlmap -u <URL> -D users -T accounts --columns
  ```

### **Extracting Data**
- `--dump`: Dumps data from all tables and databases.
- `-D <database_name> -T <table_name> --dump`: Dumps data from a specific table.
  ```bash
  sqlmap -u <URL> -D users -T accounts --dump
  ```
- `--dump-all`: Dumps data from all databases (use with caution on larger DBs).

### **Specific Data Extraction**
- `-C "<columns>"`: Specifies columns to extract, used with `--dump`.
  ```bash
  sqlmap -u <URL> -D users -T accounts -C "username,password" --dump
  ```

### **Authentication and Session Management**
- `--auth-type=<type>` and `--auth-cred="<username>:<password>"`: For basic, digest, NTLM, or certificate-based authentication.
- `--proxy=<proxy>`: Uses a proxy for all connections (e.g., `http://localhost:8080`).
- `--proxy-cred="<username>:<password>"`: Adds proxy authentication.
- `--headers="<headers>"`: Adds custom headers, e.g., `--headers="User-Agent: custom"`.
  
### **HTTP Request Methods and Headers**
- `-r <request_file>`: Uses a saved request file (ideal for complex POST requests).
- `--method=<method>`: Specifies HTTP method (e.g., `PUT`, `DELETE`, `HEAD`).
- `--user-agent="<user_agent>"`: Specifies a custom User-Agent string.
- `--referer="<referer>"`: Sets a referer header to mimic common browsing behavior.
  
### **Advanced Techniques and Options**
- `--os-shell`: Attempts to spawn an OS shell (requires high privilege).
- `--sql-shell`: Opens a SQL shell to run custom SQL commands on the database.
- `--file-read=<file_path>`: Attempts to read server files (requires access permissions).
- `--file-write=<local_file>` and `--file-dest=<remote_path>`: Uploads files to the target server.
  
### **Bypassing WAFs and Firewalls**
- `--tamper=<script>`: Uses tamper scripts to modify payloads and bypass filters.
  - Example scripts: `between.py`, `space2comment.py`
  ```bash
  sqlmap -u <URL> --tamper=space2comment.py
  ```
- `--delay=<seconds>`: Adds a delay between requests to avoid detection.
- `--safe-url=<URL>` and `--safe-freq=<freq>`: Re-checks a safe URL between attacks to avoid detection.
  
### **Performance Optimization**
- `--threads=<num>`: Specifies the number of concurrent threads (use cautiously).
- `--time-sec=<seconds>`: Sets the time for time-based injection detection.
  
### **Post-Exploitation**
- `--os-pwn`: Attempts privilege escalation on the operating system.
- `--priv-esc`: Searches for privilege escalation vulnerabilities in the DBMS.
- `--sqlmap-shell`: Provides an interactive SQL shell for advanced commands.

---
