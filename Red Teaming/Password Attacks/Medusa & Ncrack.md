
---

### **Medusa**

**Medusa** is a fast, modular, and parallel brute-force tool similar to Hydra. It supports various protocols and is particularly useful when brute-forcing multiple hosts simultaneously.
#### Common Medusa Commands
```bash
# Basic syntax:
medusa -h <target> -u <username> -P <password_list> -M <protocol>

# Examples:
# SSH brute-force:
medusa -h 192.168.1.1 -u admin -P passwords.txt -M ssh

# FTP brute-force with multiple hosts:
medusa -H hosts.txt -L usernames.txt -P passwords.txt -M ftp
```

#### When to Use Medusa
- **Multiple Hosts**: If you need to target multiple IP addresses at once.
- **Service Modules**: If you require support for unique services or want to customize protocols.
- **Real-Time Control**: When you need more control over the attack process than Hydra provides.

---

### **Ncrack**

#### Common Ncrack Commands
```bash
# Basic syntax:
ncrack -u <username> -P <password_list> <protocol>://<target>

# Examples:
# SSH brute-force:
ncrack -u admin -P passwords.txt ssh://192.168.1.1

# RDP brute-force:
ncrack -u administrator -P passwords.txt rdp://192.168.1.1

# Multiple services (e.g., SSH and FTP on the same target):
ncrack -u user -P passwords.txt ssh://192.168.1.1 ftp://192.168.1.1
```

#### When to Use Ncrack
- **Speed and Efficiency**: When speed is critical, Ncrack often performs faster on network services like RDP, SSH, and VNC.
- **Timing Control**: If you need fine-grained control over the connection and timing settings to avoid detection or reduce server load.
- **High-Value Network Protocols**: Ncrack excels in targeting network-based protocols, especially useful for penetration tests focusing on remote login services.

---

### **Hydra vs. Medusa vs. Ncrack: When to Use Each**

| **Tool**   | **Best For**                                                        | **Notable Features**                                                                                                 |
|------------|---------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **Hydra**  | Versatile brute-forcing across many protocols, single host-focused  | Highly versatile, supports many protocols, good for single-host or small target lists.                               |
| **Medusa** | Simultaneous brute-forcing on multiple hosts, modular capabilities  | Supports multiple hosts at once, custom modules for uncommon protocols.                                              |
| **Ncrack** | High-speed brute-forcing of network services like SSH, RDP, VNC     | Optimized for speed on network services, highly configurable timing options, efficient on network-heavy protocols.    |

---

### **Comparison with John and Hashcat**

Hydra, Medusa, and Ncrack are primarily **network brute-forcing tools** targeting live services. In contrast, **John the Ripper** and **Hashcat** are **password-cracking tools** focused on offline password hash cracking:

- **John the Ripper**: Known for its adaptability in cracking many types of hashes (e.g., MD5, SHA, NTLM) and its ability to apply rules for smarter dictionary attacks.
- **Hashcat**: Known for its GPU support, which allows it to crack hashes faster than CPU-based tools, making it ideal for large hash dumps or complex algorithms.

---

