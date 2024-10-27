From an **offensive security perspective**, understanding and cracking password hashes involves three main steps: recognizing the hash type, selecting the right tools to crack it, and interpreting its format based on context.

### 1. **Recognizing Hash Types**
   Hashes differ by **length**, **format**, and **prefixes**. Automated tools like **hashID** or **hashcat**'s built-in detection can help, but it’s often necessary to rely on context and experience. Here are a few tips for identifying common hash types:

   - **Linux Password Hashes**: Stored in `/etc/shadow`, Linux hashes often have prefixes indicating the algorithm used. For example:
     - `$y$` for **yescrypt**
     - `$2b$`, `$2y$`, `$2a$`, `$2x$` for **bcrypt**
     - `$6$` for **sha512crypt**
     - `$1$` for **md5crypt**
   
   - **Windows Password Hashes**: Typically use **NTLM** hashes, a variant of MD4, and are stored in the **SAM** (Security Accounts Manager) file. These hashes can appear visually similar to MD4 or MD5, so it’s crucial to recognize them based on where they’re found (e.g., SAM dump) or the system they originate from.

   - **Other Common Hashes**:
     - **MD5**: 32 characters, often used in web applications and older databases.
     - **SHA-1**: 40 characters, used in older systems.
     - **SHA-256/512**: 64 and 128 characters respectively, often seen in high-security systems.

### 2. **Extracting Hashes**
   - **Linux Systems**: Use `sudo cat /etc/shadow` to view hashes if you have root access. Each line in the shadow file represents a user, and the second field contains the password hash.
   - **Windows Systems**: Use tools like **mimikatz** or **pwdump** to extract hashes from the SAM file. Note that Windows typically stores both **LM** and **NTLM** hashes.

### 3. **Interpreting Hash Format in Linux**
   - Linux password hashes in `/etc/shadow` have the following format:
     ```plaintext
     $prefix$options$salt$hash
     ```
   - Example: `$y$j9T$76UzfgEM5PnymhQ7TlJey1$/OOSg64dhfF.TigVPdzqiFang6uZA4QA1pzzegKdVm4`
     - `y`: Algorithm prefix (yescrypt in this case)
     - `j9T`: Parameters for the algorithm
     - `76UzfgEM5PnymhQ7TlJey1`: Salt
     - `/OOSg64dhfF.TigVPdzqiFang6uZA4QA1pzzegKdVm4`: Actual hash value

### 4. **Cracking Hashes**
   - **Common Tools**:
     - **Hashcat**: Versatile and powerful for cracking a wide variety of hash types, including bcrypt, SHA-512, NTLM, and others.
     - **John the Ripper**: Often used for Linux password hashes and some application-specific hashes.
     - **CrackStation** or **Hashes.com**: These websites use massive rainbow tables for common hash types (like MD5 and NTLM). Inputting the hash into these sites can yield instant results if it’s a common password.

   - **Salts**: Salts add complexity to cracking, as each salted hash requires its own computation. This is where brute-forcing with tools like Hashcat or John the Ripper can be resource-intensive.
     - For **bcrypt** or **yescrypt** (Linux), salts are typically built into the hash.
     - For **NTLM** (Windows), the hash doesn’t have a salt, making it easier to crack with rainbow tables.

### 5. **Using Hashcat for Cracking (Example)**
   If you have an NTLM hash to crack:
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist.txt
   ```
   - **-m 1000** specifies NTLM hash mode.
   - **-a 0** specifies dictionary attack mode.
   - **hashfile.txt** contains the hash you want to crack.
   - **wordlist.txt** is your dictionary file.

### 6. **Using Context to Recognize Hash Types**
   - **Location**: Hashes found in `/etc/shadow` are most likely in a Linux-compatible format, with prefixes like `$6$` (SHA-512) or `$2y$` (bcrypt).
   - **Application-Specific Hashes**: Research can help identify obscure formats. For example, some applications use proprietary hashing algorithms or additional encodings. The **Hashcat Example Hashes page** is a valuable resource for reference.

