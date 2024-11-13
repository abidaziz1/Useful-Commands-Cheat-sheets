The **GitTools** repository is a collection of tools used for finding sensitive information within Git repositories. This includes searching for past commits, checking for sensitive data in files, and analyzing `.git` folders that may expose data accidentally.

Here’s a guide on using **GitTools** effectively:

### 1. **Clone the Repository**
First, clone the GitTools repository from GitHub. Open your terminal and run:

```bash
git clone https://github.com/internetwache/GitTools.git
cd GitTools
```

The repository contains three main tools:

- **GitDumper**: Used to download `.git` directories from a website.
- **Extractor**: Helps extract files from the `.git` folder and recover commit information.
- **GitFinder**: Scans a domain for accessible `.git` directories.

### 2. **Using GitDumper**

**GitDumper** is used to download the `.git` folder from a URL. You’ll need to know the website URL where the Git repository is accessible.

**Usage:**
```bash
./GitDumper/gitdumper.sh <target_url> <output_directory>
```

**Example:**
```bash
./GitDumper/gitdumper.sh http://example.com/.git/ dump
```

- `target_url`: URL where the `.git` directory is exposed.
- `output_directory`: Directory where the downloaded `.git` files will be stored.

**Note:** Ensure you have permission to perform this action on a target site to avoid legal issues.

### 3. **Using Extractor**

After you’ve downloaded the `.git` directory, you can use **Extractor** to retrieve commit information and content.

**Usage:**
```bash
./Extractor/extractor.sh <git_directory> <output_directory>
```

**Example:**
```bash
./Extractor/extractor.sh dump dump_extracted
```

- `git_directory`: The folder where GitDumper stored the `.git` data.
- `output_directory`: Directory where extracted files will be saved.

This script recovers files and metadata from the `.git` directory, allowing you to inspect previous states of the repository, which might contain sensitive information like API keys, passwords, or secrets.

### 4. **Using GitFinder**

**GitFinder** is useful if you want to check a domain for exposed `.git` folders. 

**Usage:**
```bash
python3 GitFinder/gitfinder.py <domain>
```

**Example:**
```bash
python3 GitFinder/gitfinder.py example.com
```

- `domain`: The target domain to check for accessible `.git` directories.

**GitFinder** scans the specified domain for accessible `.git` directories, helping you identify potential security issues.

### 5. **Inspecting Extracted Data**

Once the data is extracted, you can use standard Git commands to review it:

```bash
cd <output_directory>
git log --oneline
```

This command will show you a list of commits, which you can inspect individually:

```bash
git show <commit_hash>
```

### 6. **Cleaning Up**

Once you have reviewed the data, you may wish to remove the extracted `.git` data from your system:

```bash
rm -rf dump dump_extracted
```

### Important Considerations

- **Permissions**: Only use GitTools on systems or repositories you have explicit permission to audit.
- **Sensitive Data**: Be cautious with any sensitive information you discover and handle it responsibly.
- **Legal**: Downloading `.git` data without permission can violate security and privacy laws.

By following these steps, you can effectively utilize the GitTools repository to identify and analyze potentially exposed Git data. Let me know if you’d like more specific details on any of the steps!
