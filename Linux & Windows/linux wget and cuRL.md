### **cURL Commands with Short Descriptions**  

1. **Basic cURL Command**:  
   ```bash
   curl https://example.com/
   ```  
   Fetches raw data from the specified URL.  

2. **Progress Meter**:  
   ```bash
   curl -# https://example.com/
   ```  
   Displays a progress meter for the download.  

3. **Save File with Custom Name**:  
   ```bash
   curl -o output.html https://example.com/
   ```  
   Saves the output as `output.html`.  

4. **Save File with Original Server Name**:  
   ```bash
   curl -O https://example.com/file.zip
   ```  
   Saves the file with its original name from the server.  

5. **Resume Broken Download**:  
   ```bash
   curl -C - -O https://example.com/file.zip
   ```  
   Resumes a download without specifying the offset.  

6. **Limit Download/Upload Rate**:  
   ```bash
   curl --limit-rate 100K https://example.com/file.zip
   ```  
   Limits speed to 100KB/s.  

7. **User Authentication**:  
   ```bash
   curl -u user:password https://example.com/
   ```  
   Authenticates with the given username and password.  

8. **Upload a File to a Server**:  
   ```bash
   curl -T localfile.txt https://example.com/upload/
   ```  
   Uploads `localfile.txt` to the server.  

9. **Access via Proxy**:  
   ```bash
   curl -x proxy.server.com:8080 -u user:password https://example.com/
   ```  
   Uses the specified proxy server with optional authentication.  

10. **Fetch Only Headers**:  
    ```bash
    curl -I https://example.com/
    ```  
    Fetches HTTP headers without the webpage content.  

11. **Specify User Agent**:  
    ```bash
    curl -A "Mozilla/5.0" https://example.com/
    ```  
    Sets a custom User-Agent string.  

12. **Follow Redirects**:  
    ```bash
    curl -L https://example.com/
    ```  
    Follows HTTP redirects.  

13. **Send Cookies**:  
    ```bash
    curl -b "SESSIONID=12345" https://example.com/
    ```  
    Sends cookies with the request.  

14. **POST Data to Server**:  
    ```bash
    curl -d "username=user&password=pass" https://example.com/login
    ```  
    Posts form data to the server.  

15. **Specify HTTP Method**:  
    ```bash
    curl -X GET https://example.com/
    ```  
    Specifies the HTTP method (e.g., GET, POST).  

### **Additional Notes**:  
- Supports multiple protocols (HTTP, HTTPS, FTP, Telnet, POP, IMAP, etc.).  
- Use `man curl` for detailed information on all flags and protocols.  
- Great for automating web requests and managing file transfers.

Here are some additional **cURL** commands with their descriptions for advanced usage:

---

### **Extra Important cURL Commands**

1. **Download Multiple Files**:  
   ```bash
   curl -O https://example.com/file1.txt -O https://example.com/file2.txt
   ```  
   Downloads multiple files from different URLs with their original server names.  

2. **Verbose Output**:  
   ```bash
   curl -v https://example.com/
   ```  
   Displays detailed information about the request and response, including headers and connection details.  

3. **Silent Mode (No Output)**:  
   ```bash
   curl --silent https://example.com/
   ```  
   Suppresses progress and error messages.  

4. **Follow Redirects Verbosely**:  
   ```bash
   curl -L -v https://example.com/
   ```  
   Follows redirects while providing detailed logs.  

5. **Specify HTTP Headers**:  
   ```bash
   curl -H "Authorization: Bearer <token>" https://api.example.com/data
   ```  
   Adds custom HTTP headers to the request.  

6. **Download File to Standard Output (stdout)**:  
   ```bash
   curl https://example.com/file.txt
   ```  
   Outputs the file content directly to the terminal instead of saving it.  

7. **Save Headers to a File**:  
   ```bash
   curl -I https://example.com/ > headers.txt
   ```  
   Writes the response headers to `headers.txt`.  

8. **Specify Request Timeout**:  
   ```bash
   curl --max-time 10 https://example.com/
   ```  
   Sets the maximum time for the request to 10 seconds.  

9. **Test HTTP Methods**:  
   ```bash
   curl -X PUT -d '{"key":"value"}' -H "Content-Type: application/json" https://api.example.com/resource
   ```  
   Sends a `PUT` request with JSON data to an API.  

10. **Download via FTP**:  
    ```bash
    curl ftp://example.com/file.txt --user user:password
    ```  
    Downloads a file from an FTP server using authentication.  

11. **Extract and Save Cookies**:  
    ```bash
    curl -c cookies.txt https://example.com/
    ```  
    Saves cookies from the server to a file named `cookies.txt`.  

12. **Upload with a PUT Request**:  
    ```bash
    curl -T file.txt -X PUT https://example.com/upload
    ```  
    Uploads a file to the server using the `PUT` method.  

13. **Send JSON Data**:  
    ```bash
    curl -H "Content-Type: application/json" -d '{"key":"value"}' https://api.example.com/
    ```  
    Posts JSON data to a server.  

14. **Limit Connection Time**:  
    ```bash
    curl --connect-timeout 5 https://example.com/
    ```  
    Limits the connection time to 5 seconds.  

15. **Simulate Different Browser**:  
    ```bash
    curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com/
    ```  
    Uses a custom user-agent to mimic a specific browser.  

16. **Follow Redirects and Save to File**:  
    ```bash
    curl -L -o downloaded.html https://shorturl.example/
    ```  
    Follows redirects and saves the result to `downloaded.html`.  

17. **Send Multiple Headers**:  
    ```bash
    curl -H "Header1: Value1" -H "Header2: Value2" https://example.com/
    ```  
    Sends multiple headers in the request.  

18. **Send a File as Form Data**:  
    ```bash
    curl -F "file=@localfile.txt" https://example.com/upload
    ```  
    Uploads a file as form data.  

19. **Download Files Quietly**:  
    ```bash
    curl -s -O https://example.com/largefile.zip
    ```  
    Downloads a file without showing progress or logs.  

20. **Test a Proxy Connection**:  
    ```bash
    curl -x http://proxy.example.com:8080 https://example.com/
    ```  
    Uses a specified proxy server to make the request.  

---

### **Pro Tips**:
- Combine flags for complex operations. For example:  
  ```bash
  curl -L -H "Authorization: Bearer <token>" -o data.json https://api.example.com/resource
  ```  
  Follows redirects, authenticates, and saves the response as `data.json`.  
- Use `man curl` or `curl --help` for the complete list of flags and their uses.  

### **wget Commands with Short Descriptions**

1. **Basic File Download**:  
   ```bash
   wget https://example.com/file.zip
   ```  
   Downloads the file from the given URL.  

2. **Download in Background**:  
   ```bash
   wget -b https://example.com/file.zip
   ```  
   Runs the download process in the background.  

3. **Resume a Partial Download**:  
   ```bash
   wget -c https://example.com/file.zip
   ```  
   Resumes an interrupted or partial download.  

4. **Set Number of Retries**:  
   ```bash
   wget -t 5 https://example.com/
   ```  
   Retries up to 5 times if the download fails.  

5. **Specify Output Filename**:  
   ```bash
   wget -O custom_name.zip https://example.com/file.zip
   ```  
   Saves the file as `custom_name.zip`.  

6. **Log Output to a File**:  
   ```bash
   wget -o log.txt https://example.com/
   ```  
   Writes the logs of the download process to `log.txt`.  

7. **Append Logs to an Existing File**:  
   ```bash
   wget -a existing_log.txt https://example.com/
   ```  
   Appends logs to `existing_log.txt` without overwriting.  

8. **Read URLs from a File**:  
   ```bash
   wget -i urls.txt
   ```  
   Downloads files from the list of URLs specified in `urls.txt`.  

9. **Specify Login Credentials**:  
   ```bash
   wget --user=username --password=password https://example.com/
   ```  
   Downloads with the given username and password.  

10. **Prompt for Password**:  
    ```bash
    wget --ask-password https://example.com/
    ```  
    Asks for a password interactively for login.  

11. **Limit Download Speed**:  
    ```bash
    wget --limit-rate=100k https://example.com/file.zip
    ```  
    Limits the download speed to 100KB/s.  

12. **Set Wait Time Between Downloads**:  
    ```bash
    wget -w=10 https://example.com/
    ```  
    Waits 10 seconds before starting the next download.  

13. **Set Download Timeout**:  
    ```bash
    wget -T=30 https://example.com/
    ```  
    Times out if the download doesn’t start within 30 seconds.  

14. **Enable Timestamping**:  
    ```bash
    wget -N https://example.com/file.zip
    ```  
    Only downloads the file if it is newer than the local copy.  

15. **Specify User-Agent**:  
    ```bash
    wget -U "Mozilla/5.0" https://example.com/
    ```  
    Uses a custom user-agent string.  

---

### **Additional Notes**:
- **FTP Support**: Works with FTP servers using similar flags.  
- **Batch Processing**: Use the `-i` flag for batch downloads.  
- **Versatile**: Great for automation scripts requiring downloads.  

Use `man wget` for the complete list of flags and advanced usage examples!
