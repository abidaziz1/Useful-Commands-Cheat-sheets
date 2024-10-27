
---

### Basic Command Structure
```bash
hashcat -m <hash-type> -a <attack-mode> <hash-file> <wordlist-or-mask>
```
- **-m**: Specifies the hash type (e.g., 0 for MD5, 1000 for NTLM, 1800 for SHA-512).
- **-a**: Specifies the attack mode (0 = Dictionary, 3 = Mask, 6 = Hybrid Wordlist + Mask, etc.).

---

### Common Hash Types (`-m`)
- **0**: MD5
- **100**: SHA-1
- **1400**: SHA-256
- **1800**: SHA-512
- **1000**: NTLM (Windows)
- **3200**: bcrypt
- **500**: MD5(Unix)
- **1500**: descrypt (Unix)

---

### Attack Modes (`-a`)
- **0**: Dictionary Attack - Uses a wordlist to try passwords.
- **1**: Combination Attack - Combines words from two wordlists.
- **3**: Mask Attack - Uses custom character masks (e.g., for brute-forcing patterns).
- **6**: Hybrid Wordlist + Mask - Appends a mask to words in a wordlist.
- **7**: Hybrid Mask + Wordlist - Prepends a mask to words in a wordlist.

---

### Advanced Hashcat Commands

#### 1. **Dictionary Attack (Wordlist)**
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist.txt
   ```
   - **Description**: Standard dictionary attack for NTLM hash type using a specified wordlist.

#### 2. **Combination Attack**
   ```bash
   hashcat -m 0 -a 1 hashfile.txt wordlist1.txt wordlist2.txt
   ```
   - **Description**: Combines entries from `wordlist1.txt` and `wordlist2.txt` to generate candidate passwords.

#### 3. **Mask Attack (Brute-force Specific Patterns)**
   ```bash
   hashcat -m 1000 -a 3 hashfile.txt ?u?l?l?l?l?d?d
   ```
   - **Description**: Mask attack on NTLM hash. This example matches an 8-character pattern: 1 uppercase, 4 lowercase, and 2 digits.

#### 4. **Hybrid Attack (Wordlist + Mask)**
   ```bash
   hashcat -m 0 -a 6 hashfile.txt wordlist.txt ?d?d?d
   ```
   - **Description**: Uses each word in the wordlist, appending a 3-digit number (e.g., password123).

#### 5. **Hybrid Attack (Mask + Wordlist)**
   ```bash
   hashcat -m 0 -a 7 hashfile.txt ?u?l?l wordlist.txt
   ```
   - **Description**: Prepends a pattern (1 uppercase, 2 lowercase) to each entry in the wordlist.

#### 6. **Toggle Case Attack**
   ```bash
   hashcat -m 1000 -a 0 --increment --increment-min=1 hashfile.txt wordlist.txt -r toggle.rule
   ```
   - **Description**: Applies the `toggle.rule` rule to toggle case on each word in the wordlist.

#### 7. **Rule-Based Attack**
   ```bash
   hashcat -m 1800 -a 0 hashfile.txt wordlist.txt -r best64.rule
   ```
   - **Description**: Applies the `best64.rule` to SHA-512 hashes to create variations of words in the wordlist (e.g., adding numbers or symbols).

#### 8. **Incremental Mask Attack**
   ```bash
   hashcat -m 0 -a 3 hashfile.txt ?a?a?a?a --increment --increment-min=1 --increment-max=4
   ```
   - **Description**: Incrementally brute-forces MD5 hash from 1 to 4 characters with all character types.

#### 9. **NTLM with Known Salt**
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist.txt --salt-file=saltfile.txt
   ```
   - **Description**: Cracks NTLM hash with a specific salt file.

#### 10. **Use GPU for Acceleration**
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist.txt --opencl-device-types 1,2
   ```
   - **Description**: Uses both CPU (1) and GPU (2) for faster cracking.

#### 11. **Limit Cracking Time**
   ```bash
   hashcat -m 1000 -a 3 hashfile.txt ?a?a?a?a --runtime 60
   ```
   - **Description**: Runs a brute-force attack for 60 minutes, useful for time-limited scenarios.

#### 12. **Specify Custom Charset**
   ```bash
   hashcat -m 0 -a 3 hashfile.txt ?d?d?d?d --custom-charset1=?lud
   ```
   - **Description**: Uses a custom charset for digits and lowercase/uppercase letters.

#### 13. **Resume from Checkpoint**
   ```bash
   hashcat -m 1000 -a 3 hashfile.txt ?d?d?d?d --restore
   ```
   - **Description**: Resumes a previously interrupted session from a checkpoint file.

#### 14. **Optimized Kernel Execution**
   ```bash
   hashcat -m 0 -a 3 hashfile.txt ?d?d?d?d --optimized-kernel-enable
   ```
   - **Description**: Optimizes kernel execution, which can be faster but may use more memory.

#### 15. **Output to File**
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist.txt -o cracked.txt
   ```
   - **Description**: Saves cracked hashes to `cracked.txt` file.

#### 16. **Benchmark Specific Hash Type**
   ```bash
   hashcat -b -m 1000
   ```
   - **Description**: Runs a benchmark for NTLM (-m 1000), showing the speed of cracking on your machine.

#### 17. **Limit Password Length**
   ```bash
   hashcat -m 0 -a 0 hashfile.txt wordlist.txt --pw-min=6 --pw-max=12
   ```
   - **Description**: Limits cracking to passwords between 6 and 12 characters.

#### 18. **Custom Separator for Output**
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist.txt --outfile-format 2 --outfile-separator ","
   ```
   - **Description**: Outputs the cracked passwords in CSV format.

#### 19. **Use Multiple Wordlists**
   ```bash
   hashcat -m 1000 -a 0 hashfile.txt wordlist1.txt wordlist2.txt
   ```
   - **Description**: Uses multiple wordlists to attempt cracking.

#### 20. **Use Pre-generated Mask File**
   ```bash
   hashcat -m 1000 -a 3 hashfile.txt -i --increment --increment-min=1 --increment-max=8 -1 ?l?d mymask.hcmask
   ```
   - **Description**: Loads masks from `mymask.hcmask` file for incremental attacks.

---

### Hashcat Rule Files

Common rules include:
- **best64.rule**: Basic password variations.
- **d3ad0ne.rule**: Aggressive mutations, good for complex passwords.
- **rockyou-30000.rule**: Mutates based on the famous RockYou list.

Use with:
```bash
hashcat -m 0 -a 0 hashfile.txt wordlist.txt -r <rulefile.rule>
```

---

### Tips for Efficient Cracking
- **Use Small Wordlists First**: Start with common password lists (e.g., RockYou).
- **Filter Results**: Use `--outfile-format` for easy parsing of results.
- **Optimize Hardware**: Enable GPUs, limit CPU threads with `-O`, and use optimized kernel mode.
- **Combine Attacks**: Use hybrid attacks to cover more ground with dictionaries and masks.

There are a few additional advanced options and strategies in Hashcat that could be useful for complex cracking scenarios. Here’s a deeper dive into some additional features and tips:

---

### 1. **Working with Sessions and Checkpoints**
   - **Save a Session**: Useful for long cracking tasks, where you might need to pause and resume.
     ```bash
     hashcat -m 0 -a 3 hashfile.txt ?a?a?a?a --session mysession
     ```
   - **Restore a Session**: Resume from where it left off.
     ```bash
     hashcat --session mysession --restore
     ```

### 2. **Exhaustion Check**
   - **Command**: `--keep-guessing`
   - **Description**: By default, Hashcat stops once it finds a match. Adding `--keep-guessing` makes Hashcat continue cracking after finding the first match, which is useful when you have multiple hashes and want to crack them all without stopping.
     ```bash
     hashcat -m 0 -a 0 hashfile.txt wordlist.txt --keep-guessing
     ```

### 3. **Adjusting Performance Settings**
   - **Workload Profile**: Hashcat allows you to choose the workload profile (0 to 3). Higher values consume more GPU but increase speed.
     ```bash
     hashcat -m 0 -a 3 hashfile.txt ?a?a?a?a --workload-profile 3
     ```
     - **0**: Minimum (useful for multitasking)
     - **1**: Default
     - **2**: Medium
     - **3**: Maximum (may affect system responsiveness)

### 4. **Chained Rules**
   - **Command**: `-r`
   - **Description**: You can chain multiple rule files to increase the complexity of transformations applied to the dictionary.
     ```bash
     hashcat -m 0 -a 0 hashfile.txt wordlist.txt -r rule1.rule -r rule2.rule
     ```

### 5. **Using Preprocessed Mask Files for Efficiency**
   - **.hcmask Files**: Create a custom `.hcmask` file to specify masks for efficient brute-force attacks.
   - Example `.hcmask` file:
     ```
     ?u?l?l?l?d?d?d
     ?u?l?d?d
     ?u?u?l?d?d
     ```
   - Command to use `.hcmask`:
     ```bash
     hashcat -m 1000 -a 3 hashfile.txt -i mymask.hcmask
     ```

### 6. **Combination with External Tools**
   - **Piping Output from Other Tools**: Combine Hashcat with other tools like **Crunch** for dynamic mask generation.
     ```bash
     crunch 8 8 abcdefghijklmnopqrstuvwxyz | hashcat -m 0 hashfile.txt -a 0 --stdout | hashcat -m 0 -a 3
     ```

### 7. **Setting Exhaustive Cracking Options for Complex Passwords**
   - **Toggle Case (`-t 1`)**: Makes Hashcat toggle each character's case, useful for common words where case might vary.
   - **Character Permutation (`-t 2`)**: Applies a permutation on each candidate (mixes characters' positions).
   - **Append or Prepend (`-t 3`, `-t 4`)**: Useful if specific characters are appended or prepended regularly.

### 8. **Specialized Hash Types with Non-Standard Options**
   - **Office/OpenCL Hashing**: For cracking specific applications like MS Office, WPA, or PDF.
     - For WPA (Wi-Fi) hash cracking:
       ```bash
       hashcat -m 2500 -a 0 wpa.hccapx wordlist.txt
       ```
     - For PDF passwords:
       ```bash
       hashcat -m 10500 -a 0 pdfhash.txt wordlist.txt
       ```

### 9. **CPU-Specific Tuning Options**
   - **OpenCL Device Types**: Use `--opencl-device-types` to specify only CPU or GPU.
     - **1** = CPU, **2** = GPU
     ```bash
     hashcat -m 0 -a 3 hashfile.txt ?a?a?a?a --opencl-device-types 1
     ```

### 10. **Debugging and Detailed Output**
   - **Show Cracking Progress and Debug Information**:
     - `--status` displays cracking status at regular intervals.
     - `--debug-mode` with `--debug-file` saves failed passwords for later analysis.
     ```bash
     hashcat -m 0 -a 0 hashfile.txt wordlist.txt --status --debug-mode 4 --debug-file debug.txt
     ```

### 11. **Limit by GPU Temperature or Usage**
   - Set `--gpu-temp-abort` to stop Hashcat if the GPU temperature exceeds a threshold.
   - Use `--gpu-accel` to control how many passwords are processed per kernel execution, which can help manage temperature.
   ```bash
   hashcat -m 0 -a 3 hashfile.txt ?a?a?a?a --gpu-temp-abort=80 --gpu-accel=32
   ```

### 12. **Advanced Filtering of Results**
   - **Outfile Format (`--outfile-format`)**: Control the format of results.
     - `1` = hash, `2` = plain, `3` = salt, `4` = hex_plain, `5` = username
     ```bash
     hashcat -m 0 -a 0 hashfile.txt wordlist.txt --outfile cracked.txt --outfile-format 2
     ```

### 13. **Cracking Password Lists with Known Patterns**
   - If you have a large hash file with patterns, use **Rules** and **Masks** strategically.
   - For example, if passwords are alphanumeric with a trailing special character:
     ```bash
     hashcat -m 0 -a 3 hashfile.txt ?a?a?a?a?a?a?a?a?s
     ```

### 14. **Command to Match Password Lengths**
   - **Limit by Length (`--pw-min` and `--pw-max`)**: Ensures that only passwords within a specific length range are tried.
     ```bash
     hashcat -m 0 -a 0 hashfile.txt wordlist.txt --pw-min=8 --pw-max=12
     ```

### 15. **Run Multiple Commands in Sequence (Scripted Attacks)**
   - For complex cracking, automate commands in a bash script, each targeting different patterns or hashes.

   ```bash
   #!/bin/bash
   hashcat -m 0 -a 0 hashfile.txt wordlist1.txt
   hashcat -m 0 -a 3 hashfile.txt ?u?l?l?l?d?d
   hashcat -m 0 -a 6 hashfile.txt wordlist2.txt ?d?d
   ```

### Useful Tips
- **Custom Charset (`-1`)**: Define custom characters to focus on specific patterns.
- **Multiple Rules with `-j` and `-k`**: Apply custom rules to manipulate password candidates in hybrid attacks.
- **Dynamic Analysis**: Track progress and resource consumption with **--status**, especially useful for long cracking sessions.
  
---

