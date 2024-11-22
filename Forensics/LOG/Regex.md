Regex (regular expressions) is a powerful tool in cybersecurity blue teaming for tasks like log analysis, threat hunting, or detecting anomalies. Let’s break this down into practical use cases and regex examples for blue teaming:

---

## **1. Detecting Suspicious File Names**
Many malware files have unusual or specific naming patterns.

- **Goal:** Match files with double extensions (e.g., `file.txt.exe`).
  - **Regex:** `\w+\.\w+\.\w+$`
  - Explanation:  
    - `\w+`: Matches one or more word characters.
    - `\.`: Matches a literal period.
    - `$`: End of the string.

- **Use:** Search through logs for suspicious file uploads/downloads.

---

## **2. Extracting IP Addresses**
Often, you need to find IP addresses in logs for further analysis.

- **Goal:** Match IPv4 addresses.
  - **Regex:** `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
  - Explanation:  
    - `\b`: Word boundary ensures the match is isolated.
    - `\d{1,3}`: Matches 1 to 3 digits.
    - `\.`: Matches the literal dot.

- **Goal:** Match IPv6 addresses.
  - **Regex:** `([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`

---

## **3. Detecting Suspicious Command Injections**
Identify potential injection attacks in log files.

- **Goal:** Match common command injection patterns.
  - **Regex:** `(;|\||&&|\\)|(\$\{.*\})|(%.*%)`
  - Explanation:  
    - `(;|\||&&|\\)`: Matches common shell separators (`;`, `|`, `&&`, `\`).
    - `\$\{.*\}`: Detects environment variable injection (`${...}`).
    - `%.*%`: Detects Windows variable injection.

---

## **4. Finding Base64 Encoded Strings**
Base64 is often used for obfuscation.

- **Goal:** Match Base64 strings.
  - **Regex:** `([A-Za-z0-9+/]{4}){2,}([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`
  - Explanation:  
    - `[A-Za-z0-9+/]`: Matches Base64 characters.
    - `{4}`: Matches groups of 4 characters.
    - `==|=`: Matches padding at the end.

---

## **5. Extracting Email Addresses**
Email addresses are key in identifying phishing attempts.

- **Goal:** Match email addresses.
  - **Regex:** `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
  - Explanation:  
    - `[a-zA-Z0-9._%+-]+`: Matches local parts of emails.
    - `@`: Matches the `@` symbol.
    - `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`: Matches domain names.

---

## **6. Detecting SQL Injection Patterns**
SQL injections often have specific strings.

- **Goal:** Match SQL injection attempts.
  - **Regex:** `(\bSELECT\b|\bDROP\b|\bUNION\b|\bINSERT\b|\bDELETE\b|\b--\b|')`
  - Explanation:  
    - `\b`: Word boundary ensures full keyword matches.
    - `|`: Alternation for matching any listed keyword.
    - `'`: Matches a single quote.

---

## **7. Filtering Out URLs**
URLs in logs can be extracted or filtered.

- **Goal:** Match URLs.
  - **Regex:** `https?:\/\/[^\s\/$.?#].[^\s]*`
  - Explanation:  
    - `https?`: Matches `http` or `https`.
    - `:\/\/`: Matches `://`.
    - `[^\s\/$.?#]`: Avoids matching separators.
    - `[^\s]*`: Matches the rest of the URL.

---

## **8. Matching Time Stamps**
Time stamps are key in correlating events.

- **Goal:** Match ISO 8601 time stamps.
  - **Regex:** `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`
  - Explanation:  
    - `\d{4}`: Matches the year.
    - `-`: Matches the dash separator.
    - `T`: Matches the time delimiter.

---

## **9. Detecting Suspicious File Paths**
File paths can indicate malicious activity.

- **Goal:** Match Windows file paths.
  - **Regex:** `[A-Za-z]:\\[^\0<>:"|?*]+`
  - Explanation:  
    - `[A-Za-z]:\\`: Matches drive letters with a backslash.
    - `[^\0<>:"|?*]+`: Excludes invalid file path characters.

- **Goal:** Match Unix file paths.
  - **Regex:** `(\/[A-Za-z0-9._-]+)+`
  - Explanation:  
    - `(\/[A-Za-z0-9._-]+)+`: Matches Unix directories and filenames.

---

## **10. Identifying Large Numbers**
To find large values like file sizes in logs.

- **Goal:** Match numbers larger than 999.
  - **Regex:** `\b\d{4,}\b`
  - Explanation:  
    - `\d{4,}`: Matches numbers with 4 or more digits.

---

### **How to Practice**
1. **Sandbox Environment:** Use tools like `Regex101` to test regex with log samples.
2. **Log Files:** Practice parsing Apache, Nginx, or SIEM logs.
3. **Regex in Tools:** Apply regex in tools like Splunk, ELK Stack, or SIEM platforms.



---

### **Log Parsing and Anomaly Detection**

1. **Match Failed Login Attempts**
   - **Regex:** `(?i)failed login|authentication failure|invalid credentials`
   - Matches common login failure patterns.

2. **Detect SSH Brute-Force Attempts**
   - **Regex:** `sshd.*(Failed password|Invalid user)`
   - Used to find brute-force patterns in SSH logs.

3. **Find Suspicious Login Times**
   - **Regex:** `\b(2[3-4]|0[0-2]):[0-5]\d:[0-5]\d\b`
   - Matches logins between 11 PM and 2 AM.

4. **Extract Status Codes from Web Logs**
   - **Regex:** `\b\d{3}\b`
   - Matches HTTP status codes like `200`, `404`.

5. **Match Long Execution Times**
   - **Regex:** `execution time: \d{4,}ms`
   - Finds processes taking over 1000ms.

---

### **Network Monitoring**

6. **Detect MAC Addresses**
   - **Regex:** `([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`
   - Matches MAC address format `XX:XX:XX:XX:XX:XX`.

7. **Capture Port Numbers**
   - **Regex:** `\b\d{1,5}\b`
   - Matches valid port numbers (1–65535).

8. **Detect DNS Requests**
   - **Regex:** `\b[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}\b`
   - Matches domain names in DNS logs.

9. **Match Unusual Protocols**
   - **Regex:** `(?i)(telnet|ftp|tftp)`
   - Detects use of less secure protocols.

10. **Filter Non-RFC 1918 IPs**
    - **Regex:** `(?!(10\.|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168))\b\d{1,3}(\.\d{1,3}){3}\b`
    - Matches public IP addresses, excluding private ranges.

---

### **Threat Hunting**

11. **Detect Common Malware Extensions**
    - **Regex:** `\.(exe|bat|dll|scr|ps1|vbs)$`
    - Matches suspicious file extensions.

12. **Match Potential Ransomware Notes**
    - **Regex:** `(?i)(decrypt|ransom|bitcoin)`
    - Looks for terms indicating ransomware.

13. **Identify Large File Transfers**
    - **Regex:** `size=(\d{7,})`
    - Finds transfers over 1MB.

14. **Detect Suspicious User-Agent Strings**
    - **Regex:** `(?i)(curl|wget|python-requests)`
    - Matches known scraping tools.

15. **Find Encoded PowerShell Commands**
    - **Regex:** `(?i)powershell.*-encodedcommand [A-Za-z0-9+/=]+`
    - Detects obfuscated PowerShell commands.

---

### **SIEM/ELK Stack Queries**

16. **Filter Privilege Escalation Commands**
    - **Regex:** `(?i)(sudo|su -|chmod 777|chown root)`
    - Finds privilege escalation attempts.

17. **Match Data Exfiltration via HTTP**
    - **Regex:** `GET|POST .* HTTP/1\.\d`
    - Identifies large HTTP requests.

18. **Detect File Changes**
    - **Regex:** `(?i)(create|delete|modify) file`
    - Logs file creation, deletion, or modification.

19. **Identify Excessive Login Attempts**
    - **Regex:** `(login|auth).*(\b5\b|\b10\b|\b20\b)`
    - Detects multiple failed login attempts.

20. **Filter Rare Error Codes**
    - **Regex:** `\b(500|502|503|504)\b`
    - Matches server error status codes.

---

### **Email Security**

21. **Detect Spoofed Emails**
    - **Regex:** `(?i)(reply-to|from):.*@(example\.com|domain\.com)`
    - Matches potential spoofed email headers.

22. **Extract Suspicious Email Links**
    - **Regex:** `http(s)?:\/\/[^\s]*\.(ru|cn|xyz)`
    - Detects links to high-risk domains.

23. **Match Phishing Keywords**
    - **Regex:** `(?i)(urgent|verify|click here|reset password)`
    - Finds common phishing terms.

24. **Identify Obfuscated Email Attachments**
    - **Regex:** `attachment=.*\.(zip|7z|rar)`
    - Matches potentially harmful attachments.

25. **Extract Email Addresses from Logs**
    - **Regex:** `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
    - Standard email regex.

---

### **Filesystem Monitoring**

26. **Find Temporary Files**
    - **Regex:** `\.(tmp|temp|swp)$`
    - Matches temporary file extensions.

27. **Detect Hidden Files in Unix**
    - **Regex:** `\/\.[a-zA-Z0-9._-]+`
    - Matches hidden files starting with a dot.

28. **Match File Permissions**
    - **Regex:** `[rwx-]{10}`
    - Detects file permission strings like `-rw-r--r--`.

29. **Locate Backup Files**
    - **Regex:** `.*\.bak$`
    - Matches files ending in `.bak`.

30. **Detect Large Directory Names**
    - **Regex:** `[A-Za-z0-9._-]{50,}`
    - Matches unusually long directory or file names.

---

### **Tips for Practice and Application**

- **Tools to Test Regex:** Use platforms like [Regex101](https://regex101.com), or test them in your SIEM (Splunk, ELK Stack).
- **Integrated Systems:** Apply these regex patterns in log parsers like Graylog, Kibana, or Splunk.
- **Experimentation:** Download sample logs (e.g., Apache logs, SSH logs) and experiment with regex patterns.
