### **What is DAST?**

**Dynamic Application Security Testing (DAST)** refers to the process of testing a running web application to identify vulnerabilities by simulating attacks in real-time. Unlike Static Application Security Testing (SAST), which analyzes the source code, DAST looks at the application from a "black-box" perspective—essentially, it tests the application as an attacker would, without access to the source code.

### **How DAST Works**

DAST tools simulate attacks on a live application to identify weaknesses. These tools can find vulnerabilities during runtime that are specific to the deployment process and cannot be detected by analyzing the code alone. For example, they can uncover issues like HTTP request smuggling, cache poisoning, and parameter pollution. By testing the application while it's running, DAST tools can also detect runtime-specific vulnerabilities that wouldn't be apparent in static code analysis.

### **Manual vs. Automated DAST**

1. **Manual DAST**:
   - Performed by a security engineer who manually tests the application for vulnerabilities.
   - Useful for finding complex security issues that automated tools might miss, especially from a business logic perspective.
   - More thorough but time-consuming, making it impractical for frequent checks during active development.

2. **Automated DAST**:
   - Tools scan the application automatically to identify vulnerabilities.
   - Efficient for continuous testing in development phases, as they provide quick feedback on vulnerabilities after each change.
   - Faster and scalable but may miss certain complex vulnerabilities that require a deeper understanding of the application logic.

### **DAST in the Software Development Lifecycle (SDLC)**

DAST tools are typically used during the **testing phase** of the SDLC. Automated DAST tools help catch low-hanging vulnerabilities early in development by providing quick scans. Manual DAST scans, which are more thorough, are generally performed periodically and are used for more intensive vulnerability checks, often before the application is deployed to production.

### **Pros and Cons of DAST**

#### **Pros**:
1. **Finds runtime vulnerabilities**: Identifies issues that can only be seen during the application's execution (e.g., configuration issues, server-side issues).
2. **Language-agnostic**: Doesn't depend on the programming language of the application because it tests the live application through a black-box approach.
3. **Fewer false positives**: Compared to SAST, DAST tends to produce fewer false positives, as it tests the application in real-time.
4. **Can find business logic flaws**: Some tools can detect vulnerabilities related to business logic, although this depends on the tool and is often not a replacement for manual testing.

#### **Cons**:
1. **Limited code coverage**: DAST may miss vulnerabilities in specific scenarios or pages that are triggered only under certain conditions or during specific user interactions.
2. **Complex apps can be hard to crawl**: Modern JavaScript-heavy applications may be difficult for DAST tools to navigate, as they rely on client-side scripting.
3. **Doesn’t provide remediation details**: Since DAST is focused on testing the application externally, it doesn't provide detailed insights into how to fix the underlying code vulnerabilities.
4. **Requires a running application**: The application must be up and running for DAST to function, limiting its use during development or in environments where access to the live application is restricted.

### **DAST Tasks**

DAST tools perform at least two key tasks when testing a web application:

1. **Spidering/Crawling**: 
   - The tool automatically explores the application to map its pages and identify which parts are vulnerable. It searches for potential entry points, such as input fields and parameters, that can be attacked.

2. **Vulnerability Scanning**: 
   - After mapping the application, the tool launches predefined attack payloads against the identified pages and parameters. It tries various attack techniques, such as SQL injection, cross-site scripting (XSS), and command injection, to test for vulnerabilities.

### **Using DAST with ZAP Proxy**

For this demonstration, **ZAP (OWASP Zed Attack Proxy)** is used as a DAST tool. ZAP is a popular, open-source tool that allows security engineers to perform security testing on web applications. 

ZAP performs automated scans to identify vulnerabilities, similar to other enterprise-level tools, but with the added benefit of being free and customizable. It includes features like:

- **Spidering**: Automatically navigating through the application to identify all accessible pages and parameters.
- **Scanning**: Testing for common vulnerabilities, such as SQL injection, XSS, and file inclusion flaws.
- **Manual Penetration Testing**: Security engineers can use ZAP to test manually as well, in addition to automated scans.

### **Key Takeaways**
- **DAST** is an essential part of application security, focusing on runtime vulnerabilities and providing black-box testing.
- **Automated DAST** tools help find vulnerabilities quickly and efficiently, especially useful in fast-paced development environments.
- **Manual DAST** is more thorough but slower, identifying vulnerabilities based on deep understanding and business logic.
- DAST complements other methods like SAST, with each providing a unique approach to identifying vulnerabilities in applications.
### **Spidering an Application with ZAP**

The first step in using **ZAP (OWASP Zed Attack Proxy)** for web application testing is to **map out all the resources** of the target website. Spidering is the process of crawling the website and identifying the URLs, forms, and other components that are accessible.

Here’s a step-by-step guide on how to use ZAP to spider a website:

### **1. Using ZAP's Spidering Module**

To spider the website:

1. **Open ZAP** and go to **Tools -> Spider**.
   - This opens the Spider dialog where you can set parameters for the spidering process.
   
2. **Enter the Target URL**:
   - In the Spider dialog, input the target URL, for example, `http://MACHINE_IP:8082/`. This is the starting point where the spider will begin crawling.

3. **Configure Spidering Options** (optional):
   - **Recurse**: If checked, the spider will follow links it finds on the starting page and keep crawling the discovered pages recursively.
   - **Spider Subtree Only**: Limits the spidering to just the subfolders of the specified starting URL.
   - **Show Advanced Options**: Provides additional configuration for fine-tuning the spidering behavior.

4. **Start the Scan**:
   - Once configured, click **Start Scan**. The spider will start crawling the website from the provided starting URL.

### **2. Viewing the Sites Tab**

Once the scan begins, you can view the discovered resources in the **Sites tab** in ZAP:
   - This tab will populate with all the URLs the spider has found during its scan.
   - The URLs listed will be the ones directly found through hyperlinks or other accessible means. Any resources outside the initial URL scope won't be included.

### **3. Spider Limitations**
By default, ZAP uses a simple spidering method that processes the website's HTML responses. However, modern web applications often rely on **JavaScript** to dynamically generate links or content. This can cause limitations in standard spidering:
   - **JavaScript-generated links** may not be captured because the ZAP spider does not process JavaScript.
   - For instance, if you manually navigate to `http://MACHINE_IP:8082/`, you might see a link like `/nospiders-gallery.php` that is dynamically added by JavaScript. However, the ZAP Spider might not detect this link.

### **4. Overcoming Spidering Limitations with AJAX Spider**

To overcome the limitation of not crawling JavaScript-rendered content, ZAP offers an **AJAX Spider**. This spider works by leveraging a real browser (like **Firefox** or **Chrome**) to process JavaScript, ensuring that dynamic content generated by JavaScript is captured.

To use the **AJAX Spider**:

1. **Go to Tools -> AJAX Spider**.
   - This opens the AJAX Spider dialog, where you can configure the scan settings.
   
2. **Configure the Starting URL**:
   - Just like the regular spider, specify the starting point URL (e.g., `http://MACHINE_IP:8082/`).

3. **Select the Browser**:
   - Choose **Firefox** for the browser selection to make sure the spider uses a real browser to process the JavaScript and retrieve the resulting HTML.

4. **Start the Scan**:
   - Click **Start Scan**. ZAP will launch Firefox, which will navigate the website, process JavaScript, and retrieve the fully rendered page.

### **5. Reviewing Results**

Once the AJAX Spider completes, you should notice that:
   - The **Sites tab** in ZAP will now include previously missing URLs, such as `/nospiders-gallery.php`, which are dynamically generated by JavaScript.
   - The AJAX Spider uses Firefox's processing power, ensuring a more accurate and complete list of pages and resources.

### **Conclusion**

- **Regular Spider**: Works by crawling the static HTML of the website. It is fast but may miss JavaScript-generated content.
- **AJAX Spider**: Uses an actual browser (e.g., Firefox) to render the page and capture links generated by JavaScript. It ensures dynamic content is also crawled.

By combining both spidering techniques, you can ensure that your web application is fully mapped, capturing both static and dynamic content, and giving you a comprehensive understanding of the app's structure.
### **Configuring a Scan Policy in ZAP for Optimized Testing**

When using **Dynamic Application Security Testing (DAST)** tools like **ZAP**, it's essential to tailor the scan policy based on the application's specific characteristics. This ensures that only relevant tests are conducted, reducing unnecessary tests that could slow down the scanning process and focusing on vulnerabilities that actually apply to the target environment.

### **Why Customize Scan Policies?**

Customizing the scan policy helps:
- **Speed up the scan** by eliminating irrelevant tests.
- **Reduce false positives** by focusing on vulnerabilities likely to exist in the target environment.
- **Optimize the scan** based on known details about the application and its infrastructure.

### **Steps to Create or Modify a Scan Policy**

1. **Navigate to the Scan Policy Manager**:
   - In ZAP, go to **Analyse -> Scan Policy Manager**.

2. **Add a New Scan Policy**:
   - In the Scan Policy Manager, click the **Add** button to create a new scan policy.

### **Configuring Scan Policy Categories**

For each category in the scan policy, you'll configure two main parameters:
1. **Threshold**: This controls how sensitive the scan is in detecting vulnerabilities:
   - **Low**: ZAP reports vulnerabilities with a lower certainty, meaning it may report more issues (higher risk of false positives).
   - **Medium/High**: ZAP only reports vulnerabilities that it’s more certain about, which reduces false positives but may miss some vulnerabilities (higher risk of false negatives).
   - **OFF**: Completely disables a category (useful if that category isn’t relevant to your application).

2. **Strength**: This controls the number of tests run for a given category:
   - **Low Strength**: Fewer tests, quicker scan, but potentially missing some issues.
   - **Medium/High Strength**: More thorough tests, but may take longer to complete.

### **Configuring the Policy for Our Application**

Given the specifics of the application we are testing:
- **Operating System**: Linux
- **Web Server**: Apache 2.4
- **Programming Language**: PHP (no frameworks)
- **Databases**: None

We can **disable certain types of tests** that are irrelevant to the application:

1. **Disable Database-Related Tests**:
   - Since there’s no database used in the application, tests like **SQL Injection** can be disabled to speed up the scan.

2. **Disable XML Tests**:
   - If the application doesn't involve XML processing, disable tests for **XML External Entity (XXE)** and other XML-related vulnerabilities.

3. **Disable DOM-Based Cross-Site Scripting (XSS) Tests**:
   - These tests can be very resource-intensive. Since they aren't as critical for this example, disable them to optimize the scan.

The customized **Injection Policy** will look something like this:
- Disable **SQL Injection** tests.
- Disable **XML Injection** tests.
- Disable **DOM-based Cross-Site Scripting** tests.

### **Running the First Scan with the Custom Policy**

1. **Start the Active Scan**:
   - After setting the scan policy, go to **Tools -> Active Scan**.
   - Select the starting URL (e.g., `http://MACHINE_IP:8082/`) from the list of previously spidered URLs.
   - Check the **Recurse** box to ensure that all pages linked from the starting URL are also scanned.

2. **Click Start Scan**:
   - Start the scan, and ZAP will begin testing the web application based on your configured scan policy.

### **Reviewing the Results**

1. **Checking Alerts**:
   - Once the scan completes, you will see the **Alerts** tab populate with detected issues.
   - For each alert, ZAP provides a description of the vulnerability found, along with the specific request and response that triggered the alert.

2. **False Positives**:
   - If you believe an alert is a **false positive**, you can right-click on the finding in the Alerts tab and select **Mark as False Positive**. This helps refine the scan results and ensure more accurate reporting for future scans.

### **Conclusion**

Customizing the scan policy in ZAP is a key step in improving scan efficiency and accuracy. By disabling irrelevant tests and adjusting the thresholds and strength for relevant categories, you can reduce scan time, avoid unnecessary tests, and focus on detecting vulnerabilities that are most likely to exist in your specific application. This ensures a more tailored and effective security assessment.
### **Dealing with Logins in ZAP (OWASP Zed Attack Proxy)**

When performing a **Dynamic Application Security Test (DAST)** with ZAP, dealing with authentication is essential to ensure the scanner can check all parts of the application, especially those that are restricted to logged-in users. In this task, we will guide you through configuring ZAP to handle login authentication so that it can access protected areas of your application during the scan.

### **Disabling ZAP HUD**
Before starting, **disable the ZAP HUD (Head-Up Display)** from the toolbar. Some features may not work as expected if the HUD is enabled. You can find the button to disable it at the top of the toolbar in ZAP.

### **Recording Authentication with ZAP**

To enable ZAP to authenticate and maintain session states, we need to **record the login process** and replay it during scanning.

1. **Recording a New ZEST Script**:
   - Click the **Record a New ZEST Script** button on the toolbar.
   - Set a **title** for your script (e.g., "Authentication Script").
   - Choose the **Authentication** type and set the **prefix** to your base application URL (e.g., `http://MACHINE_IP:8082/`) to filter out requests to external sites.

2. **Start Recording**:
   - Click **Start Recording**. ZAP will now record every HTTP request passing through the proxy.
   - Open a browser from ZAP using the **Open Browser** button on the toolbar, and navigate to the login page of your application (e.g., `http://MACHINE_IP:8082/login.php`).

3. **Login Manually**:
   - Enter the credentials for the web application:
     - **Username**: `nospiders`
     - **Password**: `nospiders`
   - Once logged in, click the **Record a New ZEST Script** button again to stop the recording.

4. **Review Recorded Requests**:
   - Some requests that are not part of the authentication process may have been captured. You can delete any unnecessary requests, leaving only those necessary for login, typically the **POST** request to `login.php` and the **redirect** response to `cowsay.php` (indicating a successful login).

5. **Test the Recorded Script**:
   - In the **Script Console**, click **Run** to test if the recorded process works correctly. ZAP should replay the login steps, and the application should respond with the redirection to `cowsay.php`.

### **Creating a Context in ZAP**

A **Context** in ZAP allows us to define a set of URLs and associate them with specific behaviors like authentication. We need to create a context that covers the entire application and link the recorded authentication script to it.

1. **Create a New Context**:
   - Go to the **Sites** tab, right-click the base URL of the application, and select **Include in Context -> New Context**.
   - ZAP will automatically generate a regex to include all URLs under the base URL.

2. **Link Authentication Script**:
   - In the **Context** settings, go to **Authentication**.
   - Choose **Script-based Authentication**, click **Load** next to the script name, and select your recorded ZEST script.

3. **Define Users**:
   - You must define at least one user in the **Users** section to perform authenticated scans. Since the user credentials are embedded in the ZEST script, ZAP will automatically use those credentials during the scan.
   - **Click OK** once the context and authentication are configured.

### **Re-spidering the Application**

With the authentication configured, we now need to re-run the spider to discover any URLs that require authentication.

1. **Authenticated Spidering**:
   - Go to **Tools -> Spider** and start the scan using the new context.
   - Ensure that **Recurse** is checked to scan all pages linked from the starting URL.

2. **Monitor Results**:
   - As the spider runs, check the **Sites** tab to see newly discovered URLs. This time, ZAP will be able to access protected areas of the application that require login.

3. **Excluding Logout**:
   - Right-click the `logout.php` script in the **Sites** tab, and choose **Exclude from Context**. This prevents ZAP from logging out during the scan, which could disrupt the session.

### **Configuring Session Verification**

To ensure that ZAP maintains an active session throughout the scan, you need to set up **login and logout indicators**:

1. **Set Login Indicator**:
   - Navigate to a page accessible only to authenticated users (e.g., `cowsay.php`).
   - Right-click the text that indicates the user is logged in (e.g., the logout link) and select **Flag as Context -> Authentication Logged-in Indicator**.

2. **Set Logout Indicator**:
   - Similarly, right-click the login link on the `aboutme.php` page (visible when logged out), and select **Flag as Context -> Authentication Logged-out Indicator**.

3. **Choose a Verification Strategy**:
   - In the **Context** settings, under **Authentication**, choose **Poll the Specified URL** as the verification strategy.
   - Set the URL (e.g., `/aboutme.php`) and configure ZAP to check for login/logout indicators every 60 requests to ensure the session is still valid.

### **Running the Authenticated Scan**

Finally, you are ready to run a full authenticated scan:

1. **Start Active Scan**:
   - Go to **Tools -> Active Scan** and select the **Context** and **User** that you created.
   - ZAP will now perform an authenticated scan, checking both authenticated and unauthenticated areas of the application.

2. **Review Scan Results**:
   - After the scan completes, check the **Alerts** tab for new findings. These could include vulnerabilities that were previously inaccessible due to authentication restrictions.

### **Conclusion**

By configuring ZAP to handle authentication through a ZEST script and context, we enable it to scan protected areas of a web application. This is a crucial step in ensuring a thorough security assessment of both authenticated and unauthenticated parts of the application. The result is a comprehensive scan that reveals vulnerabilities across the entire application, improving the accuracy and depth of the security testing.
