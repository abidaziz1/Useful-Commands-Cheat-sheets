

### Basic Cmdlet Structure
- **Syntax**: `Verb-Noun -Parameter <value>`
- **Example**: `Get-Help Get-Process`

---

## **File and Directory Management**

### Listing Files and Directories
- **List all items**: `Get-ChildItem -Path "C:\Path"`
- **List with filter**: `Get-ChildItem -Path "C:\Path" -Filter "*.txt"`
- **Recursive listing**: `Get-ChildItem -Recurse`

### Changing Directories
- **Set location**: `Set-Location -Path "C:\Path"`
- **Shortcut**: `cd C:\Path`

### Creating and Removing Items
- **New Directory**: `New-Item -Path "C:\Path\NewFolder" -ItemType Directory`
- **New File**: `New-Item -Path "C:\Path\file.txt" -ItemType File`
- **Remove Item**: `Remove-Item -Path "C:\Path\file.txt"`

### Copying and Moving Items
- **Copy Item**: `Copy-Item -Path "C:\Path\file.txt" -Destination "C:\NewPath"`
- **Move Item**: `Move-Item -Path "C:\Path\file.txt" -Destination "C:\NewPath"`

### Viewing and Modifying File Content
- **View content**: `Get-Content -Path "C:\Path\file.txt"`
- **Add content**: `Add-Content -Path "C:\Path\file.txt" -Value "New line"`

---

## **System Information and Management**

### System and OS Information
- **Detailed System Info**: `Get-ComputerInfo`
- **Basic System Info**: `systeminfo` (Command Prompt compatibility)

### Process Management
- **List all processes**: `Get-Process`
- **Kill a process**: `Stop-Process -Name "notepad"`
- **Filter by resource usage**: `Get-Process | Where-Object { $_.CPU -gt 100 }`

### Service Management
- **List all services**: `Get-Service`
- **Start a service**: `Start-Service -Name "ServiceName"`
- **Stop a service**: `Stop-Service -Name "ServiceName"`

---

## **Networking**

### Network Configuration
- **IP Configuration**: `Get-NetIPConfiguration`
- **List all IP addresses**: `Get-NetIPAddress`

### TCP Connections
- **List active TCP connections**: `Get-NetTCPConnection`
- **Filter connections by state**: `Get-NetTCPConnection | Where-Object State -eq "Listen"`

### DNS and Network Adapters
- **Configure DNS server**: `Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("8.8.8.8", "8.8.4.4")`
- **Get network adapter info**: `Get-NetAdapter`

---

## **Remote Management**

### Run Commands on Remote Computers
- **Invoke Command**:
  ```powershell
  Invoke-Command -ComputerName "RemotePC" -ScriptBlock { Get-Process }
  ```
- **Run local script remotely**:
  ```powershell
  Invoke-Command -FilePath "C:\scripts\script.ps1" -ComputerName "RemotePC"
  ```

### PowerShell Remoting
- **Start a remote session**: `Enter-PSSession -ComputerName "RemotePC"`
- **Exit session**: `Exit-PSSession`

---

## **Security and Permissions**

### Managing Users and Groups
- **List local users**: `Get-LocalUser`
- **Create a new user**:
  ```powershell
  New-LocalUser -Name "NewUser" -Password (ConvertTo-SecureString "Password" -AsPlainText -Force) -FullName "User Full Name"
  ```
- **Add user to group**: `Add-LocalGroupMember -Group "Administrators" -Member "NewUser"`

### File Hashing
- **Generate file hash**: `Get-FileHash -Path "C:\Path\file.txt"`

### ACL (Access Control List)
- **View ACL**: `Get-Acl -Path "C:\Path\file.txt"`
- **Set ACL (permissions)**:
  ```powershell
  $acl = Get-Acl "C:\Path\file.txt"
  $access = New-Object System.Security.AccessControl.FileSystemAccessRule("User", "FullControl", "Allow")
  $acl.SetAccessRule($access)
  Set-Acl -Path "C:\Path\file.txt" -AclObject $acl
  ```

---

## **Scripting and Automation**

### Variables and Expressions
- **Define a variable**: `$var = "Hello"`
- **Arithmetic expression**: `$result = 5 + 3`

### Control Flow
- **If-Else Statement**:
  ```powershell
  if ($condition) { "True" } else { "False" }
  ```
- **For Loop**:
  ```powershell
  for ($i=0; $i -lt 5; $i++) { Write-Output $i }
  ```
- **Foreach Loop**:
  ```powershell
  $array = @(1,2,3)
  foreach ($item in $array) { Write-Output $item }
  ```

### Functions
- **Defining a Function**:
  ```powershell
  function Get-Greeting {
      param($name)
      Write-Output "Hello, $name!"
  }
  ```

### Scheduled Tasks
- **Create a new scheduled task**:
  ```powershell
  New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\scripts\script.ps1") -Trigger (New-ScheduledTaskTrigger -AtStartup)
  ```

---

## **Filtering and Sorting Data**

### Filtering with `Where-Object`
- **Basic filter**: `Get-Process | Where-Object { $_.CPU -gt 100 }`

### Sorting with `Sort-Object`
- **Sort by property**: `Get-ChildItem | Sort-Object Length`

### Selecting Properties
- **Select specific properties**: `Get-Process | Select-Object Name, CPU`

---

## **Data Export and Import**

### Exporting Data
- **Export to CSV**:
  ```powershell
  Get-Process | Export-Csv -Path "C:\Path\processes.csv" -NoTypeInformation
  ```
- **Export to JSON**:
  ```powershell
  Get-Process | ConvertTo-Json | Out-File "C:\Path\processes.json"
  ```

### Importing Data
- **Import from CSV**:
  ```powershell
  Import-Csv -Path "C:\Path\data.csv"
  ```
- **Import from JSON**:
  ```powershell
  Get-Content -Path "C:\Path\data.json" | ConvertFrom-Json
  ```

---

## **Text Processing**

### Searching Text with `Select-String`
- **Find pattern in file**:
  ```powershell
  Select-String -Path "C:\Path\file.txt" -Pattern "search-term"
  ```

### Replace Text in File
- **Example**:
  ```powershell
  (Get-Content -Path "C:\Path\file.txt") -replace "oldText", "newText" | Set-Content -Path "C:\Path\file.txt"
  ```

---

## **Performance Monitoring**

### Disk Usage
- **Check disk usage**:
  ```powershell
  Get-PSDrive -PSProvider FileSystem
  ```

### System Resource Monitoring
- **CPU and Memory usage**:
  ```powershell
  Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 5
  ```

---
