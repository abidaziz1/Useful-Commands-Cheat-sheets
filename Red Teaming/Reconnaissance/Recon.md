Here’s a Recon-ng cheat sheet with real-life example commands to help make it more practical:

### Initial Setup
1. **Create a Workspace for Target Organization**
   ```bash
   workspaces create example_org
  ```

2. **Set Up API Keys (if you have any)**
   ```bash
   keys add shodan_api ABCDEFGHIJKLMNOPQRST
   keys add virustotal_api 1234567890ABCDEF
   ```

3. **Database Setup (Manual Entry)**
   - To manually add a specific host:
   ```bash
   db insert hosts ip=192.168.1.1 host=target.example.com
   ```

### Basic Recon Workflow
1. **Start with Domain Enumeration**
   - Load a domain module to find hosts related to `example.com`.
   ```bash
   modules load recon/domains-hosts/brute_hosts
   options set source example.com
   run
   ```

2. **Look for Subdomains Using Bing**
   - This will search Bing for potential subdomains of `example.com`.
   ```bash
   modules load recon/domains-hosts/bing_domain_web
   options set source example.com
   run
   ```

3. **Gather Contacts (Emails) from Whois Records**
   ```bash
   modules load recon/domains-contacts/whois_pocs
   options set source example.com
   run
   ```

4. **Retrieve Social Profiles for Found Emails**
   - This can help map user profiles linked to gathered emails.
   ```bash
   modules load recon/contacts-profiles/profiler
   options set source email@example.com
   run
   ```

### Advanced Modules and Commands
1. **Retrieve Public Documents**
   - This module searches for publicly available documents on `example.com`.
   ```bash
   modules load recon/domains-documents/google_doc
   options set source example.com
   run
   ```

2. **Gather Geolocation Information on IP Addresses**
   - This example uses IPInfoDB to gather location data for specific IPs.
   ```bash
   modules load recon/hosts-hosts/ipinfodb
   options set source 192.168.1.1
   run
   ```

3. **Check for Vulnerabilities Using Shodan**
   - You can identify vulnerabilities in discovered hosts.
   ```bash
   modules load recon/hosts-vulnerabilities/shodan_net
   options set source example.com
   run
   ```

4. **Reverse IP Lookup to Discover Domains Sharing IP**
   - Useful for finding additional sites hosted on the same server.
   ```bash
   modules load recon/hosts-hosts/reverse_resolve
   options set source 192.168.1.1
   run
   ```

### Automate Common Steps with a Script
- Create a `.rc` file to automate a workflow for `example.com`:

   ```plaintext
   workspaces select example_org
   modules load recon/domains-hosts/brute_hosts
   options set source example.com
   run
   modules load recon/domains-contacts/whois_pocs
   options set source example.com
   run
   report html example_org_report.html
   exit
   ```

- Run the automation file:
   ```bash
   resource example_script.rc
   ```

### Exporting and Reporting
1. **Export Hosts to CSV**
   ```bash
   db export hosts.csv
   ```

2. **Generate an HTML Report**
   ```bash
   report html example_report.html
   ```

3. **Export Contacts to a JSON File**
   ```bash
   report json contacts_report.json
   ```

4. **Generate a PDF Report for Presentation**
   ```bash
   report pdf final_report.pdf
   ```

### Example Recon Flow
1. **Identify Subdomains, Gather Emails, and Search for Vulnerabilities**
   ```bash
   workspaces create target_company
   modules load recon/domains-hosts/brute_hosts
   options set source targetcompany.com
   run
   modules load recon/domains-contacts/whois_pocs
   options set source targetcompany.com
   run
   modules load recon/hosts-vulnerabilities/xssposed
   options set source targetcompany.com
   run
   ```

2. **Reverse Resolve IPs Found on Host**
   ```bash
   modules load recon/hosts-hosts/reverse_resolve
   options set source 104.26.1.1
   run
   ```

3. **Gather Social Media Information for Targeted Emails**
   ```bash
   modules load recon/contacts-profiles/profiler
   options set source person@example.com
   run
   ```
These real-life commands streamline the information-gathering process across various recon stages. By using these command examples, you’ll efficiently map out hosts, find potential vulnerabilities, and enrich data with social and geographical context.
