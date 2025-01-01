### **On-Premises IaC: A Deep Dive**

---

### **What is On-Premises IaC?**
On-premises Infrastructure as Code (IaC) involves managing and deploying systems and services within an organization’s internal network. All resources—servers, storage, and networking—are hosted locally in the company’s data center, giving the organization full control over its infrastructure.

---

### **Why Use On-Prem IaC?**
While cloud-based solutions dominate the modern landscape, **on-prem IaC** remains relevant for certain scenarios:

1. **Control**:
   - Organizations have full ownership of their IaC pipeline, including infrastructure, configurations, and security.
   - Example: A self-hosted GitLab instance allows full-stack control compared to GitHub, which shifts security responsibilities to a third party.

2. **Compliance**:
   - On-prem IaC is often preferred in industries with strict data protection regulations (e.g., finance, government).
   - Sensitive data can remain within the organization’s physical boundaries, ensuring compliance with data sovereignty requirements.

3. **Customization**:
   - The pipeline can be tailored to specific business or operational needs.
   - On-prem setups can enforce unique security measures, such as restricting access to internal VPNs.

---

### **Benefits of On-Prem IaC**
1. **Full Control**:
   - Every layer, from infrastructure to the IaC toolchain, is managed in-house.
2. **Customizable Pipelines**:
   - The ability to fine-tune every component of the deployment process.
3. **Enhanced Data Protection**:
   - Keeps sensitive data off third-party systems, simplifying compliance.
4. **Cost Savings Over Time**:
   - Avoids recurring monthly fees for hosting the IaC pipeline.
5. **Efficient for Small Deployments**:
   - On-prem resources can be directly utilized for targeted deployments.

---

### **Drawbacks of On-Prem IaC**
1. **Responsibility for Security**:
   - The organization is fully accountable for securing and maintaining its infrastructure.
2. **Limited Scalability**:
   - Scaling requires physical resources, which can lead to either resource shortages or over-investment.
3. **High Initial Costs**:
   - Setting up on-premises infrastructure involves significant upfront investments in hardware and setup.

---

### **Tools for On-Prem IaC**
Two commonly used tools for managing on-prem IaC are **Vagrant** and **Ansible**.

#### **1. Vagrant**:
   - **Purpose**: Simplifies the creation and management of virtualized environments for development and testing.
   - **How It Works**:
     - Uses lightweight virtual machines to create consistent environments.
     - Ideal for local development setups where teams need identical infrastructure.
   - **Best Use Cases**:
     - Testing new software or configurations on isolated VMs before deploying to production.

#### **2. Ansible**:
   - **Purpose**: A configuration management tool for automating software provisioning and infrastructure management.
   - **How It Works**:
     - Uses playbooks (written in YAML) to define desired configurations.
     - Agentless, so it doesn’t require installation on target systems, making it simpler to use.
   - **Best Use Cases**:
     - Automating deployments, updates, and configuration changes on physical or virtual servers.

---

### **When to Choose On-Prem IaC**
1. **Regulated Industries**:
   - Organizations bound by strict compliance, such as banking or government.
2. **Custom Requirements**:
   - Businesses needing highly customized deployment pipelines.
3. **Sensitive Data**:
   - Scenarios where third-party hosting poses unacceptable security risks.
4. **Established Infrastructure**:
   - Companies with existing physical infrastructure they wish to optimize.

---

### **Conclusion**
On-prem IaC is not a one-size-fits-all solution, but it is indispensable for organizations requiring high control, compliance, and customization. While the initial investment and management overhead are significant, the trade-offs can be worthwhile for scenarios that prioritize data security and operational independence. Tools like **Vagrant** and **Ansible** make the process more manageable, enabling organizations to automate and streamline their on-premises infrastructure efficiently.

### **Vagrant: Simplified On-Prem IaC for Development**

---

### **What is Vagrant?**
Vagrant is a tool used to create and manage **portable virtual development environments**. It works like a "big brother" to Docker, handling not just container instances but also provisioning the servers to host them. 

Think of Vagrant as a script-based system to define and set up virtual machines (VMs) consistently, making it a great choice for on-premises IaC.

---

### **Key Terminology**
- **Provider**:
  - The virtualization platform used by Vagrant.
  - Examples: Docker, VirtualBox, VMware, AWS.
- **Provision**:
  - Actions performed on a host during deployment (e.g., adding files, running scripts).
- **Configure**:
  - Changes made to a host’s setup (e.g., adding network interfaces, setting a hostname).
- **Variable**:
  - Stores values used in the deployment script.
- **Box**:
  - Predefined images (e.g., Ubuntu) that Vagrant uses to create virtual machines.
- **Vagrantfile**:
  - The main provisioning script for Vagrant.

---

### **Example Vagrant Setup**
#### **Folder Structure**
```
.
├── provision
│   ├── files.zip
│   └── script.sh
└── Vagrantfile
```

#### **Vagrantfile Script**
```ruby
Vagrant.configure("2") do |cfg|
  cfg.vm.define "server" do |config|
    config.vm.box = "ubuntu/bionic64"
    config.vm.hostname = "testserver"
    config.vm.provider :virtualbox do |v, override|
       v.gui = false 
       v.cpus = 1
       v.memory = 4096
    end

    config.vm.network :private_network,
        :ip => 172.16.2.101
    config.vm.network :private_network,
        :ip => 10.10.10.101
  end

  cfg.vm.define "server2" do |config|
    config.vm.box = "ubuntu/bionic64"
    config.vm.hostname = "testserver2"
    config.vm.provider :virtualbox do |v, override|
       v.gui = false 
       v.cpus = 2
       v.memory = 4096
    end

    #Upload resources
    config.vm.provision "file", source: "provision/files.zip", destination: "/tmp/files.zip"

    #Run script
    config.vm.provision "shell", path: "provision/script.sh"
  end
end
```

---

### **What Does This Do?**
1. **Two Servers Created**:
   - **Server 1**:
     - **Base Image**: Ubuntu Bionic 64-bit.
     - **Resources**: 1 CPU, 4GB RAM.
     - **Network**: Two private interfaces with static IPs.
   - **Server 2**:
     - **Base Image**: Ubuntu Bionic 64-bit.
     - **Resources**: 2 CPUs, 4GB RAM.
     - **Provisioning**:
       - Uploads `files.zip` to `/tmp/`.
       - Executes the `script.sh` file.

2. **Provision Command**:
   - Run `vagrant up` to provision both servers in the order specified.
   - Run `vagrant up server` to provision a specific server by name.

---

### **Benefits of Vagrant for IaC**
1. **Consistency**:
   - Ensures all team members use the same virtual environments.
2. **Flexibility**:
   - Supports multiple providers (e.g., VirtualBox, Docker, VMware).
3. **Customizability**:
   - Define detailed configurations for each host (CPUs, memory, networking).
4. **Ease of Use**:
   - Simple commands to bring up or destroy environments (`vagrant up`, `vagrant destroy`).

---

### **Real-Life Use Case**
Using Vagrant with **VirtualBox**, you can create an Active Directory (AD) network with:
- Two domain controllers.
- A server.
- A workstation.

This is useful for testing and simulating network configurations. Explore repositories online for ready-made Vagrantfiles to see how provisioning is performed.

---

### **Next Steps**
We will soon create our own Vagrantfile to deploy a customized infrastructure. Start experimenting with the provided example, and you'll be ready to build robust on-prem IaC deployments in no time!
### **Ansible: Simplifying On-Prem IaC**

---

### **What is Ansible?**
Ansible is an open-source tool for automating Infrastructure as Code (IaC). Unlike Vagrant, Ansible focuses on **configuration management**, ensuring systems reach and maintain their desired state. It uses **version control** for execution steps, meaning it only updates what’s necessary, making it highly efficient for managing infrastructure.

---

### **Key Terminology**
- **Playbook**: A YAML file defining steps for provisioning and configuring hosts.
- **Template**: A base file with placeholders (e.g., configuration files) that get filled in at runtime with values from Ansible variables.
- **Role**: A collection of templates, tasks, and variables that can be assigned to a host. Roles allow reusability and modular design.
- **Variable**: Stores values for use in the playbook. Variables can be grouped into files, allowing different configurations based on the environment (e.g., staging or production).

---

### **Folder Structure in Ansible**
An example structure:

```
.
├── playbook.yml
├── roles
│   ├── common
│   │   ├── defaults
│   │   │   └── main.yml
│   │   ├── tasks
│   │   │   ├── apt.yml
│   │   │   ├── main.yml
│   │   │   ├── task1.yml
│   │   │   ├── task2.yml
│   │   │   └── yum.yml
│   │   ├── templates
│   │   │   ├── template1
│   │   │   └── template2
│   │   └── vars
│   │       ├── Debian.yml
│   │       └── RedHat.yml
│   ├── role2
│   ├── role3
│   └── role4
└── variables
    └── var.yml
```

---

### **Ansible Playbook Example**

#### **`playbook.yml`**
```yaml
---
- name: Configure the server
  hosts: all
  become: yes
  roles:
    - common
    - role3
  vars_files:
    - variables/var.yml
```

- **What It Does**:
  - Applies the `common` and `role3` roles to all hosts.
  - Overrides default role variables using `var.yml`.

#### **`tasks/main.yml`**
```yaml
---
- name: include OS specific variables
  include_vars: "{{ item }}"
  with_first_found:
    - "{{ ansible_distribution }}.yml"
    - "{{ ansible_os_family }}.yml"

- name: set root password
  user:
    name: root
    password: "{{ root_password }}"
  when: root_password is defined

- include: apt.yml
  when: ansible_os_family == "Debian"

- include: yum.yml
  when: ansible_os_family == "RedHat"

- include: task1.yml
- include: task2.yml
```

- **What It Does**:
  - Identifies the OS type (e.g., Debian or RedHat).
  - Executes OS-specific tasks using `apt.yml` or `yum.yml`.
  - Sets the root password (if defined).
  - Runs additional tasks in `task1.yml` and `task2.yml`.

---

### **Combining Vagrant and Ansible**
Using **Vagrant for host provisioning** and **Ansible for configuration** is a powerful combo.

#### **Vagrantfile with Ansible**
```ruby
config.vm.provision "ansible_local" do |ansible|
    ansible.playbook = "provision/playbook.yml"
    ansible.become = true
end
```

- **What Happens**:
  - Vagrant provisions the VM(s).
  - Ansible configures the provisioned hosts using the `playbook.yml`.

---

### **Vagrant vs. Ansible: Key Differences**

| **Aspect**                | **Vagrant**                          | **Ansible**                          |
|---------------------------|---------------------------------------|---------------------------------------|
| **Configuration Language**| Ruby (Vagrantfiles).                 | YAML (Playbooks).                    |
| **Integration**           | Works with Chef, Puppet, or Ansible. | Works standalone or with CI/CD tools.|
| **Complexity**            | Simple for small environments.       | Scales better for complex systems.   |
| **Scalability**           | Limited scalability.                 | Highly scalable for large systems.   |
| **Execution Model**       | Procedural (step-by-step).           | Declarative (focus on desired state).|

---

### **Next Steps**
Now that you understand **Vagrant** and **Ansible**, let’s combine them to build your own **IaC pipeline**. You’ll use Vagrant to set up infrastructure and Ansible to handle configurations efficiently. This modular approach is flexible, scalable, and keeps your IaC workflow organized!

### **Key Security Considerations for Infrastructure as Code (IaC)**

When deploying infrastructure using IaC, whether on-premises or cloud-based, ensuring security is crucial. Here are four key elements to consider and address to secure your IaC pipeline effectively.

---

### **1. Dependencies**
- **Risk**: The IaC pipeline relies on dependencies like base images, which may introduce vulnerabilities if outdated or insecure.
- **Example**:
  - A vulnerable OS image used in provisioning could expose all deployed hosts to potential attacks.
- **Best Practices**:
  - Regularly update base images and dependencies.
  - Use trusted sources for base images or maintain a private repository.
  - Implement automated dependency scanning tools to identify vulnerabilities.

---

### **2. Defaults**
- **Risk**: Using default credentials or configurations during provisioning is common but leaving them unchanged creates significant vulnerabilities.
- **Examples**:
  - **Default Credentials**:
    - Vagrant’s default Windows user (`vagrant:vagrant`) not being removed post-deployment.
    - Jenkins installed with default credentials (`jenkins:jenkins`) and left unchanged.
  - **Insecure Services**:
    - Services deployed with default open ports or configurations that remain unaltered.
- **Best Practices**:
  - Automate the removal or alteration of default credentials at the final provisioning step.
  - Ensure deployed services require initial credentials to be changed before usage.
  - Document and monitor for any default settings that might pose risks.

---

### **3. Insufficient Hardening**
- **Risk**: Rapid IaC deployments often prioritize speed over security, leading to insufficiently hardened infrastructure.
- **Examples**:
  - **Pipeline-Specific Vulnerabilities**:
    - Vagrant uses WinRM for provisioning Windows hosts, which threat actors exploit for lateral movement if left enabled.
  - **Unnecessary Services**:
    - Services used during provisioning, like SSH or WinRM, remain active post-deployment.
- **Best Practices**:
  - Integrate hardening steps directly into the IaC pipeline (e.g., disabling unneeded services post-deployment).
  - Use configuration management tools (e.g., Ansible, Puppet) to enforce hardening standards.
  - Conduct regular vulnerability assessments of provisioned infrastructure.

---

### **4. Remote Code Execution as a Feature**
- **Risk**: IaC pipelines inherently execute code remotely, creating a potential attack vector if compromised.
- **Threat**:
  - Unauthorized access to the pipeline can lead to malicious code execution, infrastructure compromise, or data breaches.
- **Best Practices**:
  - **Secret Management**:
    - Store sensitive information (e.g., credentials, keys) securely using tools like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.
    - Avoid embedding secrets directly in source code.
  - **Principle of Least Privilege**:
    - Restrict pipeline access to essential users and services only.
    - Implement multi-factor authentication (MFA) and role-based access control (RBAC).
  - **Monitoring and Auditing**:
    - Continuously monitor pipeline activity for unusual behavior.
    - Maintain logs of pipeline actions and access events for audit purposes.

---

### **Practical Steps to Secure Your IaC Pipeline**
1. **Dependency Management**:
   - Regularly scan for vulnerabilities in dependencies and ensure updates.
2. **Default Configuration Handling**:
   - Automate the removal or updating of defaults in the final provisioning steps.
3. **Pipeline Hardening**:
   - Include post-deployment hardening tasks in your IaC pipeline.
   - Disable provisioning-related services when no longer needed.
4. **Access and Secret Management**:
   - Secure sensitive information with dedicated secret management tools.
   - Follow RBAC and MFA practices to control pipeline access.

---

### **Next Steps**
With these security practices in mind, you’re better equipped to protect IaC pipelines from real-world threats. The next step is applying this knowledge to test and secure an IaC pipeline or identify vulnerabilities in a simulated environment.

