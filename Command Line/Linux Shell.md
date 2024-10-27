

---

### Basic Commands
```bash
# Show current directory
pwd

# List files in the current directory
ls

# Change directory
cd /path/to/directory

# Copy files or directories
cp source destination

# Move files or directories
mv source destination

# Remove files or directories
rm filename
rm -r directoryname  # Recursive delete

# Create a new directory
mkdir new_directory

# Display contents of a file
cat filename

# Show file content page-by-page
less filename
```

---

### File Permissions
```bash
# View file permissions
ls -l filename

# Change file permissions
chmod 755 filename  # Owner: read/write/execute; group/others: read/execute

# Change ownership of a file
chown user:group filename

# Recursive permission change
chmod -R 755 directoryname
```

---

### File Management
```bash
# Find files by name
find /path -name "filename"

# Find files by type and delete them
find /path -type f -name "*.tmp" -delete

# Compress files using gzip
gzip filename

# Extract gzip files
gunzip filename.gz

# Archive files using tar
tar -cvf archive.tar /path/to/directory

# Extract tar files
tar -xvf archive.tar

# Create a compressed tarball
tar -czvf archive.tar.gz /path/to/directory
```

---

### Process Management
```bash
# List currently running processes
ps aux

# Display top processes
top

# Kill a process by PID
kill PID

# Kill a process by name
pkill processname

# View processes in a tree structure
pstree

# Background a process
command &

# Bring process to foreground
fg %jobnumber
```

---

### Disk Management
```bash
# Show disk usage
df -h

# Check directory size
du -sh /path/to/directory

# Check free memory
free -h

# Mount a device
mount /dev/sdb1 /mnt/usb

# Unmount a device
umount /mnt/usb

# View disk partitions
fdisk -l
```

---

### Networking
```bash
# Show IP address information
ip a

# Display routing table
route -n

# Show active network connections
netstat -tuln

# Ping an IP address
ping 8.8.8.8

# Test ports on a server
nc -zv hostname port

# Download files using wget
wget http://example.com/file.zip

# Download files using curl
curl -O http://example.com/file.zip
```

---

### User Management
```bash
# Add a new user
sudo useradd -m username

# Delete a user
sudo userdel -r username

# Add a user to a group
sudo usermod -aG groupname username

# Change user password
passwd username

# List all groups
cat /etc/group
```

---

### Text Processing
```bash
# Display first 10 lines of a file
head filename

# Display last 10 lines of a file
tail filename

# Count lines, words, and characters in a file
wc filename

# Sort lines in a file
sort filename

# Find and replace text in a file
sed -i 's/original/replacement/g' filename

# Display lines that contain a string
grep "pattern" filename
```

---

### System Information
```bash
# Display system information
uname -a

# Show kernel version
uname -r

# Display CPU information
cat /proc/cpuinfo

# Display memory information
cat /proc/meminfo

# Show running services
systemctl list-units --type=service

# Check uptime
uptime
```

---

### Scripting Basics
```bash
# Define a variable
name="John"

# Print a variable
echo "Hello, $name"

# Basic if-else condition
if [ "$name" = "John" ]; then
  echo "Welcome, John!"
else
  echo "Access Denied"
fi

# For loop example
for i in {1..5}; do
  echo "Number $i"
done

# While loop example
counter=1
while [ $counter -le 5 ]; do
  echo "Count $counter"
  ((counter++))
done
```

---

### Advanced Commands and Tricks
```bash
# Check systemd service status
systemctl status servicename

# Run command as root
sudo command

# Schedule tasks with cron
crontab -e  # Edit crontab
# Example cron job (Runs every day at midnight):
0 0 * * * /path/to/script.sh

# Show environment variables
printenv

# Add a path to PATH environment variable
export PATH=$PATH:/new/path

# Create an alias for a command
alias ll='ls -lah'

# Remove all files from a directory (dangerous!)
rm -rf /path/to/directory/*

# Run last command as sudo
sudo !!

# Create a symbolic link
ln -s /path/to/file /path/to/symlink

# Combine commands
command1 && command2  # Runs command2 only if command1 succeeds
command1 || command2  # Runs command2 only if command1 fails
```

---

### File Content Manipulation with `awk` and `sed`
```bash
# Print specific column with awk
awk '{print $1, $3}' filename

# Sum a column of numbers in a file with awk
awk '{sum+=$1} END {print sum}' filename

# Substitute text with sed
sed 's/old_text/new_text/g' filename

# Delete specific line (e.g., 5th line) with sed
sed '5d' filename

# Insert text after a specific line (e.g., 2nd line) with sed
sed '2a This is new text' filename
```

---

### Compression and Archiving
```bash
# Create a zip file
zip archive.zip file1 file2

# Unzip a zip file
unzip archive.zip

# Compress a folder using gzip
tar -czf archive.tar.gz /folder_to_compress

# Extract a gzip compressed file
tar -xzf archive.tar.gz
```

---

### SSH and Remote Connections
```bash
# Connect to a remote server
ssh username@hostname

# Copy files from local to remote server
scp localfile username@hostname:/remote/directory

# Copy files from remote server to local
scp username@hostname:/remote/file local_directory

# Run a command on a remote server
ssh username@hostname "command_to_run"
```

