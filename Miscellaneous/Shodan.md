
---

### **Introduction to Shodan**
- **Purpose**:
  - A search engine for internet-connected devices such as desktops, servers, IoT devices, and industrial systems.
  - Created by John C. Matherly in 2009.
  - Used in network security, market research, cyber risk assessment, IoT scanning, and tracking ransomware.
---

### **Core Shodan Interfaces**
1. **CLI Tool**:
   - Command-line interface for quick operations, written in Python.
   - Installation:
     ```bash
     easy_install shodan
     ```
   - Initialization:
     ```bash
     shodan init <YOUR_API_KEY>
     ```

2. **Website**:
   - Graphical interface for searching, downloading results, and generating reports.

3. **API**:
   - Allows integration with custom tools or scripts.
   - Supports multiple programming languages (Python, Ruby, Node.js, etc.).

4. **Community-Driven Libraries**:
   - Additional libraries created by the community for diverse use cases and languages.

---

### **Key CLI Commands**
1. **General Commands**:
   - **Help**:
     ```bash
     shodan --help
     ```
   - **Version**:
     Check the current version of the Shodan CLI.
     ```bash
     shodan version
     ```

2. **Query and Credits**:
   - **Account Info**:
     Check available query and scan credits.
     ```bash
     shodan info
     ```

   - **Count**:
     Returns the number of results for a search query.
     ```bash
     shodan count <query>
     ```

3. **Search**:
   - Search the Shodan database and view results directly.
     ```bash
     shodan search --fields ip_str,port,org <query>
     ```

4. **Host Information**:
   - Fetch details of an IP address, such as location, open ports, and associated organization.
     ```bash
     shodan host <IP>
     ```

5. **Data Download and Parsing**:
   - Download search results:
     ```bash
     shodan download <filename> <query>
     ```
   - Parse downloaded JSON files:
     ```bash
     shodan parse --fields ip_str,port <filename>
     ```

6. **Scanning**:
   - Scan an IP or network block:
     ```bash
     shodan scan submit <IP_or_netblock>
     ```
   - List available scan protocols:
     ```bash
     shodan scan protocols
     ```

7. **Stats**:
   - View summary statistics for a query:
     ```bash
     shodan stats <query>
     ```

8. **Stream**:
   - Access live data as Shodan collects it.
     ```bash
     shodan stream
     ```

---

### **Advanced Features**
1. **Report Generation**:
   - Create reports from search results to visualize data through graphs and charts.
   - Available directly from the web interface.

2. **Data Download Formats**:
   - JSON: Includes full data and is compatible with Shodan CLI.
   - CSV: Contains a summary (IP, port, banner, organization, and hostnames).
   - XML: Deprecated and less space-efficient.

3. **Customizable Searches**:
   - Example queries:
     - Find MongoDB instances:
       ```bash
       shodan search --fields ip_str,port,org product:mongodb
       ```
     - Search by operating system or software:
       ```bash
       shodan search "Windows 10"
       ```

---

### **Examples**
1. **Query for OpenSSH Results**:
   ```bash
   shodan count openssh
   ```
   Output:
   ```
   23128
   ```

2. **Download Data for Later Analysis**:
   ```bash
   shodan download openssh-data openssh
   ```

3. **Analyze Downloaded Data**:
   - Filter specific fields (e.g., country code, IP):
     ```bash
     shodan parse --fields location.country_code3,ip_str openssh-data.json.gz
     ```

---

### **Shodan Website Features**
1. **Main Interface**:
   - Perform searches with a user-friendly UI.
   - Includes details like vulnerabilities, open ports, and banner data for selected hosts.

2. **Report Generation**:
   - Provides an overview of how query results are distributed globally.
   - Free for all users.

3. **Download History**:
   - Access previously downloaded results for reference or further analysis.

---

This segment of the **Shodan Pentest Guide** discusses various functionalities of Shodan and how they can be utilized for penetration testing, reporting, and API integration. Here's a detailed breakdown of the key points:

---

### **Reports and Visualizations**
1. **Reports**:
   - Shodan allows users to generate static reports for analysis.
   - Reports can take a few minutes to prepare and are accessible through a report page.

2. **Maps**:
   - Interactive map interface to visualize Shodan data geographically.
   - Limitations: Displays a maximum of 1,000 results at a time; users need to zoom or pan for additional data.

3. **Images**:
   - Shodan collects screenshots from:
     - VNC
     - RDP (Remote Desktop Protocol)
     - RTSP (Real-Time Streaming Protocol)
     - Webcams
     - X Windows
   - Use the filter `has_screenshot:true` to find hosts with screenshots.

---

### **Exploits and Vulnerability Scanning**
1. **Exploit Search Engine**:
   - Searches through various exploit databases.
   - Use this tool to identify vulnerabilities relevant to specific systems or devices.

---

### **Monitoring and Alerts**
1. **Network Monitoring**:
   - Track Internet-exposed devices with the following capabilities:
     - Add IPs, ranges, or domains for monitoring.
     - Receive alerts based on customizable trigger events.
     - Launch scans directly from the dashboard.
   - Synthetic dashboards display exposed services and suspicious activities.

2. **Honeypot Detection**:
   - Honeyscore estimates the likelihood of an IP address being a honeypot.
   - Example command: `shodan honeyscore <IP>`.

---

### **Community Features**
1. **Community Queries**:
   - Users can share and browse queries with titles, descriptions, and tags for better accessibility.
   - Queries can be shared using the "Share Search" button.

---

### **REST API and Integration**
1. **Overview**:
   - REST API provides extensive capabilities for building web services or automating tasks.
   - Base URL: `https://api.shodan.io`.
   - API requests are rate-limited to 1 request per second and require authentication.

2. **Example API Queries**:
   - Retrieve API plan information:
     ```bash
     curl -s https://api.shodan.io/api-info?key=<API_KEY>
     ```
   - Get host details:
     ```bash
     curl -s https://api.shodan.io/shodan/host/<IP>?key=<API_KEY>
     ```

3. **Wrapper Libraries**:
   - Shodan supports integration in multiple languages, including Python, Ruby, Node.js, and more.

---

### **Python API Usage**
1. **Installation**:
   - Install via pip or package manager:
     ```bash
     pip install shodan
     ```

2. **Example Usage**:
   - Search for hosts:
     ```python
     import shodan

     SHODAN_API_KEY = 'your_api_key'
     api = shodan.Shodan(SHODAN_API_KEY)

     results = api.search('apache')
     print(f"Results found: {results['total']}")
     for result in results['matches']:
         print(f"IP: {result['ip_str']} - Data: {result['data']}")
     ```

   - Retrieve host information:
     ```python
     host = api.host('1.1.1.1')
     print(f"IP: {host['ip_str']} - Organization: {host.get('org', 'n/a')}")
     for service in host['data']:
         print(f"Port: {service['port']} - Banner: {service['data']}")
     ```

---

### **Ruby and Node.js API Usage**
1. **Ruby (shodanz)**:
   - Install:
     ```bash
     gem install shodanz
     ```
   - Example:
     ```ruby
     require 'shodanz'
     api = Shodanz.client.new(key: 'API_KEY')

     results = api.host_search('apache')
     results['matches'].each { |r| puts "IP: #{r['ip_str']}" }
     ```

2. **Node.js (shodan-client)**:
   - Install:
     ```bash
     npm install shodan-client
     ```
   - Example:
     ```javascript
     const api = require('shodan-client');
     const key = 'API_KEY';

     api.search('apache', key).then(results => {
         console.log('Results found:', results['total']);
     });
     ```

---

This segment emphasizes Shodan's potential for integration into automated workflows, vulnerability scanning, and visualizations. Let me know if you'd like a deeper explanation or practical examples!


---

### **Understanding Shodan Banners**
- **Banners** provide detailed information about the service or device detected, including metadata like HTTP responses or raw data from services.
- Example: HTTP 301 banner includes server type (e.g., Cloudflare), transfer protocols, and other connection-specific data.

---

### **Data Analysis Using Facets**
- **Facets** allow for aggregating data across properties (like organization, domain, port, ASN, country).
- Example:
  ```python
  FACETS = {
      'org': 3,
      'domain': 5,
      'port': 5,
      'asn': 5,
      'country': 10,
  }
  ```
- **Output Example**:
  - Top Organizations: Liquid Web, Amazon.
  - Top Ports: 80 (HTTP), 443 (HTTPS), 8080.
  - Top Countries: US, Germany, China.

---

### **Python Integration with Shodan API**
- **Basic Queries**:
  - Count total results:
    ```python
    result = api.count(query, facets=FACETS)
    print(result['total'])
    ```
  - Retrieve banners for a host:
    ```python
    host = api.host('1.1.1.1')
    for item in host['data']:
        print(f"Port: {item['port']} - Banner: {item['data']}")
    ```

---

### **Ruby Integration**
- The **Shodanz gem** allows Shodan queries in Ruby.
- Example:
  ```ruby
  results = api.host_search('apache')
  results['matches'].each do |result|
      puts "IP: #{result['ip_str']}"
  end
  ```

---

### **Node.js Integration**
- Use the `shodan-client` library for integration.
- **Basic Queries**:
  ```javascript
  api.search('apache', key).then(results => {
      console.log('Results found: ' + results['total']);
  });
  ```
- **Retrieve Host Information**:
  ```javascript
  api.host('1.1.1.1', key).then(host => {
      console.log(`IP: ${host['ip_str']} - Organization: ${host['org']}`);
  });
  ```

---

### **Advanced Shodan Features**
- **Async Operations**:
  - Shodan streaming API for real-time analysis:
    ```python
    api.streaming_api.banners do |banner|
        # Process each banner
    end
    ```
  - Requires a Freelancer or higher API plan.

- **Honeypot Detection**:
  - Calculate honeypot probability:
    ```python
    api.honeypot_score('1.1.1.1')
    ```

---

### **Common Use Cases**
1. **Port Scanning**:
   - Analyze common ports (80, 443, etc.).
   - Detect vulnerabilities like open Telnet or RDP ports.
2. **Vulnerability Scanning**:
   - Search for CVEs:
     ```bash
     shodan search vuln:cve-XXXX-XXXX
     ```
3. **IoT and ICS Devices**:
   - Identify insecure IoT systems using queries:
     ```bash
     shodan search "port:502 product:Modbus"
     ```
4. **Web Apps**:
   - Detect default installations (e.g., Jenkins):
     ```bash
     shodan search "http.favicon.hash:XXXXXX"
     ```

---

### **Shodan Browser Plugins**
- **Firefox & Chrome Add-ons**:
  - Display Shodan data for current websites.
  - Provide details on open ports and organization.

---


### **Shodan Overview**
- **Shodan Plugin**:
  - Available for Chrome; provides information about a website’s hosting location, owner IP, and other open services/ports.
  - Quickly checks if Shodan has information about the current site, including unusual services like FTP, DNS, or SSH.

### **Shodan Search Syntax**
1. **Banner and Properties**:
   - A banner in Shodan is an object with service information. For example:
     ```json
     {
       "data": "Moxa Nport Device",
       "ip_str": "46.252.132.235",
       "port": 4800,
       "org": "Starhub Mobile",
       "location": { "country_code": "SG" }
     }
     ```
   - Key properties include `data`, `ip_str`, `port`, and `location`.

2. **Search Filters**:
   - **Basic filters**:
     - `org`: Organization (e.g., `org:"Starhub Mobile"`).
     - `country`: Devices by country (e.g., `country:SG`).
     - Combine filters (e.g., `org:"Starhub Mobile" country:SG`).
   - **Complete Property List**:
     - Includes `asn`, `ip`, `hostnames`, `domains`, `location` details (city, latitude, longitude), `org`, `isp`, `os`, `port`, `transport`, and more.

### **Common Search Queries**
- **Databases**:
  - Example searches for database technologies:
    - MySQL: `product:MySQL`
    - MongoDB: `product:MongoDB`
    - Elasticsearch: `port:9200 json`
    - PostgreSQL: `port:5432 PostgreSQL`
- **Games**:
  - Minecraft: `Minecraft Server port:25565`
  - Counter-Strike: `product:"Counter-Strike Global Offensive"`

- **Industrial Control Systems**:
  - Examples:
    - Modbus devices: `port:502`
    - BACnet devices: `port:47808`

- **Vulnerabilities**:
  - Example:
    - Devices vulnerable to Heartbleed: `vuln:cve-2014-0160`.

### **Shodan Tools**
1. **CLI Examples**:
   - Count devices for a vulnerability: `$ shodan count vuln:cve-2014-0160`
   - List subdomains for a domain: `$ shodan domain example.com`
   - Monitor your network: `$ shodan alert create mynetwork 198.20.58.0/24`

2. **Third-Party Tools**:
   - ShodanSploit: Command-line tool for detailed queries.
   - Fav-Up: Retrieves real IP addresses based on favicon hashes.

3. **Shodan Alternatives**:
   - **Onyphe**: Adds data from passive DNS lookups and threat lists.
   - **Censys**: Tracks changes and sends alerts but offers limited free API.
   - **ZoomEye**: Provides detailed filters and preset queries.

### **Advanced Applications**
- **Pivoting**: Utilize property hashes for deeper analysis.
- **Shodan Data Files**: Work with historical and metadata insights.

### **Resources and Recommendations**
- The guide links to GitHub repositories and tools like:
  - Recon-ng, Spiderfoot, OWASP Amass.
  - `awesome-shodan-queries` for extensive dorking examples.

### **Acknowledgments**
- Credits to Shodan’s founder John C. Matherly and contributors from the community for their extensive work.


