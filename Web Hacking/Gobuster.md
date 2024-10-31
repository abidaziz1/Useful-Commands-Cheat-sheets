

---

## **Gobuster Advanced Cheat Sheet**

### 1. **Basic Usage Syntax**
```bash
gobuster [mode] -u [URL] -w [wordlist] [flags]
```
Modes:
- **`dir`**: Directory and file enumeration.
- **`dns`**: DNS subdomain enumeration.
- **`vhost`**: Virtual host enumeration.

---

### 2. **Directory Enumeration (`dir` Mode)**

Enumerates directories and files on a web server.

**Basic Command**:
```bash
gobuster dir -u "http://target.thm" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Common Flags in `dir` Mode**:

| Flag | Long Flag              | Description                                                           |
|------|-------------------------|-----------------------------------------------------------------------|
| `-t` | `--threads`             | Sets the number of concurrent threads.                                |
| `-w` | `--wordlist`            | Specifies the path to the wordlist.                                   |
| `-x` | `--extensions`          | Specifies file extensions to check (e.g., `.php`, `.js`, `.html`).    |
| `-r` | `--followredirect`      | Follows redirects during enumeration.                                 |
| `-c` | `--cookies`             | Sets a cookie, such as a session ID, for authenticated requests.      |
| `-H` | `--headers`             | Adds custom headers to requests (e.g., `Authorization`).             |
|      | `--delay`               | Sets a delay between requests to avoid detection.                    |
| `-o` | `--output`              | Saves output to a specified file.                                    |
| `-s` | `--status-codes`        | Filters by status code (e.g., `200`, `403`, or ranges like `300-400`).|
|      | `--exclude-length`      | Filters results by response size (useful for avoiding 404 responses). |

**Examples**:

- **1. Basic Directory Enumeration**:
  ```bash
  gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt
  ```

- **2. Directory Enumeration with File Extensions**:
  ```bash
  gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt -x .php,.js,.html
  ```

- **3. Enumeration with Custom Header and Cookie**:
  ```bash
  gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt -H "Authorization: Bearer <token>" -c "sessionID=abcd1234"
  ```

- **4. Follow Redirects and Save Results**:
  ```bash
  gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt -r -o results.txt
  ```

- **5. Filter Out 404 Responses by Excluding Response Length**:
  ```bash
  gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt --exclude-length 290
  ```

---

### 3. **Subdomain Enumeration (`dns` Mode)**

Performs brute-force DNS enumeration to find subdomains.

**Basic Command**:
```bash
gobuster dns -d target.thm -w /path/to/subdomains.txt
```

**Common Flags in `dns` Mode**:

| Flag | Long Flag              | Description                                                          |
|------|-------------------------|----------------------------------------------------------------------|
| `-d` | `--domain`              | Specifies the domain for enumeration.                                |
| `-w` | `--wordlist`            | Specifies the path to the subdomain wordlist.                        |
| `-c` | `--show-cname`          | Displays CNAME records (cannot be used with `-i` flag).              |
| `-i` | `--show-ips`            | Shows IP addresses that subdomains resolve to.                       |
| `-r` | `--resolver`            | Sets a custom DNS server for resolution.                             |
| `-o` | `--output`              | Saves results to a specified file.                                   |

**Examples**:

- **1. Basic Subdomain Enumeration**:
  ```bash
  gobuster dns -d target.thm -w /path/to/subdomains.txt
  ```

- **2. Show CNAME Records**:
  ```bash
  gobuster dns -d target.thm -w /path/to/subdomains.txt -c
  ```

- **3. Display IP Addresses of Found Subdomains**:
  ```bash
  gobuster dns -d target.thm -w /path/to/subdomains.txt -i
  ```

- **4. Use a Custom DNS Server for Resolution**:
  ```bash
  gobuster dns -d target.thm -w /path/to/subdomains.txt -r 1.1.1.1
  ```

- **5. Save Results to a File**:
  ```bash
  gobuster dns -d target.thm -w /path/to/subdomains.txt -o dns_results.txt
  ```

---

### 4. **Virtual Host Enumeration (`vhost` Mode)**

Enumerates virtual hosts on a single IP by brute-forcing possible hostnames in the "Host" header.

**Basic Command**:
```bash
gobuster vhost -u "http://10.10.10.10" -w /path/to/wordlist.txt
```

**Common Flags in `vhost` Mode**:

| Flag | Long Flag              | Description                                                          |
|------|-------------------------|----------------------------------------------------------------------|
| `-u` | `--url`                 | Specifies the target URL or IP address.                              |
| `-w` | `--wordlist`            | Specifies the wordlist for brute-forcing hostnames.                  |
|      | `--append-domain`       | Appends the domain to each wordlist entry (e.g., `blog.example.com`).|
| `-d` | `--domain`              | Sets the domain to use in the `Host` header.                         |
|      | `--exclude-length`      | Filters responses by body length (useful for false positives).       |
| `-r` | `--follow-redirect`     | Follows HTTP redirects.                                              |

**Examples**:

- **1. Basic Virtual Host Enumeration**:
  ```bash
  gobuster vhost -u "http://10.10.10.10" -w /path/to/wordlist.txt
  ```

- **2. Specify Domain and Append to Wordlist Entries**:
  ```bash
  gobuster vhost -u "http://10.10.10.10" --domain example.com -w /path/to/wordlist.txt --append-domain
  ```

- **3. Exclude Responses with a Certain Length to Filter False Positives**:
  ```bash
  gobuster vhost -u "http://10.10.10.10" -w /path/to/wordlist.txt --exclude-length 312
  ```

- **4. Custom HTTP Method (e.g., POST)**:
  ```bash
  gobuster vhost -u "http://10.10.10.10" -w /path/to/wordlist.txt -m POST
  ```

- **5. Virtual Host Enumeration with Redirect Following and Saved Output**:
  ```bash
  gobuster vhost -u "http://10.10.10.10" -w /path/to/wordlist.txt -r -o vhost_results.txt
  ```

---

### 5. **Helpful Flags for All Modes**

| Flag       | Description                                                       |
|------------|-------------------------------------------------------------------|
| `--delay`  | Sets delay between requests to prevent rate limiting or detection.|
| `--output` | Saves results to a file for review.                               |
| `--threads`| Adjusts the number of threads based on system capability.         |
| `--verbose`| Provides detailed output during execution for troubleshooting.    |

---

### Summary Tips

1. **Adjust `threads` based on resources** to optimize speed and system load.
2. **Filter responses** by excluding specific lengths to ignore false positives.
3. **Use custom DNS servers** for `dns` mode to bypass blocking or rate-limiting from default resolvers.
4. **Combine flags** like `--append-domain`, `--domain`, and `--exclude-length` in `vhost` mode to improve accuracy.

If Gobuster is running slowly, here are some optimization techniques to speed up the process:

### 1. **Increase Threads (`-t` Flag)**
   - By default, Gobuster uses 10 threads, which might be slow for large wordlists or complex scans. Increasing the number of threads will make it send requests concurrently.
   ```bash
   gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt -t 50
   ```
   - **Note**: Be cautious with very high thread counts as they can overload the target server and even crash your own machine if resources are limited.

### 2. **Use Smaller, Targeted Wordlists**
   - Instead of using massive wordlists, which can be time-consuming, try smaller, targeted lists specific to the type of target (e.g., WordPress, API endpoints). 
   - **Example**: `SecLists` has specialized lists under `/usr/share/wordlists/SecLists/Discovery/Web-Content/` on Kali Linux.

### 3. **Limit Status Codes (`-s` Flag)**
   - Specifying status codes of interest, such as `200`, `301`, or `403`, can reduce the clutter and only show successful or potentially interesting responses.
   ```bash
   gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt -s 200,301,403
   ```

### 4. **Increase Delay (`--delay` Flag) for Stability**
   - If Gobuster is hanging or being rate-limited, adding a small delay (e.g., `100ms`) can prevent rate limiting or throttling, resulting in a more stable and potentially faster scan.
   ```bash
   gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt --delay 100ms
   ```

### 5. **Use `no-tls-validation` (`-k` Flag) on HTTPS Scans**
   - Skipping TLS validation reduces SSL handshake time and is helpful when dealing with self-signed certificates.
   ```bash
   gobuster dir -u "https://target.thm" -w /path/to/wordlist.txt -k
   ```

### 6. **Optimize File Extensions (`-x` Flag)**
   - If searching for specific file types, use only the relevant extensions (e.g., `.php`, `.js`). This can save a significant amount of time.
   ```bash
   gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt -x php,js,html
   ```

### 7. **Exclude Known Irrelevant Response Lengths (`--exclude-length` Flag)**
   - Identify response lengths for typical 404 pages, and filter them out to avoid scanning them repeatedly.
   ```bash
   gobuster dir -u "http://target.thm" -w /path/to/wordlist.txt --exclude-length 300
   ```
