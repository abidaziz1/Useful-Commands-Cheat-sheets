
#### **Combining `sort` and `uniq`**
For optimal use, pipe `sort` output into `uniq`:

1. **Sort and Filter Duplicates**:  
   ```bash
   sort file.txt | uniq
   ```  
   Sorts `file.txt` and removes duplicate lines.

2. **Sort and Count Duplicate Lines**:  
   ```bash
   sort file.txt | uniq -c
   ```  
   Sorts `file.txt` and counts occurrences of each line.

---

#### **Handling Language Issues**
If the output isn’t as expected due to locale settings, reset the `$LANG` variable:
```bash
export LANG='en_US.UTF-8'
```

This ensures proper character encoding and accurate results.

### **Detailed Overview of the `sed` Command with Key Concepts and Examples**

#### **What is `sed`?**
`sed` (Stream Editor) is a versatile tool for text manipulation, including **find and replace**, **deleting**, **inserting**, and **viewing specific lines**. It works on input streams or files, making it essential for automating tasks in text processing.

---

### **Important Flags for `sed`**
| **Flag** | **Description**                                                                 |
|----------|---------------------------------------------------------------------------------|
| `-e`     | Allows multiple commands/scripts in a single `sed` command.                     |
| `-f`     | Reads commands from a script file instead of inline.                            |
| `-E`     | Enables extended regular expressions (similar to `grep -E`).                    |
| `-n`     | Suppresses automatic printing of lines; use with commands like `p` to control output. |

---

### **Key Commands (Modes)**
| **Command** | **Description**                                                                                   |
|-------------|---------------------------------------------------------------------------------------------------|
| `s`         | Substitution mode (find and replace).                                                             |
| `y`         | Byte transformation; similar to `s` but operates on characters instead of patterns.               |
| `d`         | Deletes lines matching the pattern.                                                               |
| `p`         | Prints lines matching the pattern. Combine with `-n` to avoid duplicate output.                   |

---

### **Commonly Used Flags in Patterns**
| **Flag** | **Description**                                                                                       |
|----------|-------------------------------------------------------------------------------------------------------|
| `g`      | Makes substitution global (replaces all occurrences of the pattern in each line).                     |
| `i`      | Makes the pattern search case-insensitive.                                                            |
| `/1`, `/2` | Specifies the nth occurrence of the pattern to act upon.                                              |
| `d`      | Deletes lines or patterns found in the file.                                                          |

---

### **Examples and Use Cases**

#### **1. Substitution Mode**
**Basic Find and Replace:**
```bash
sed 's/foo/bar/' file.txt
```
- Replaces the first occurrence of `foo` with `bar` in each line.

**Global Replacement:**
```bash
sed 's/foo/bar/g' file.txt
```
- Replaces all occurrences of `foo` with `bar` in each line.

**Case-Insensitive Replacement:**
```bash
sed 's/foo/bar/gi' file.txt
```
- Replaces all occurrences of `foo` (case-insensitive) with `bar`.

**Nth Occurrence Replacement:**
```bash
sed 's/foo/bar/2' file.txt
```
- Replaces the **second** occurrence of `foo` with `bar` in each line.

---

#### **2. Viewing Lines**
**Print Specific Lines:**
```bash
sed -n '5,10p' file.txt
```
- Prints lines 5 through 10.

**View Entire File Except Specific Lines:**
```bash
sed '5,10d' file.txt
```
- Deletes lines 5 through 10, showing the rest of the file.

**Print Matching Lines:**
```bash
sed -n '/error/p' file.txt
```
- Prints lines containing the word `error`.

---

#### **3. Inserting or Deleting Lines**
**Delete Lines Matching a Pattern:**
```bash
sed '/pattern/d' file.txt
```
- Deletes all lines containing `pattern`.

**Insert a Line Before/After a Match:**
```bash
sed '/pattern/i\This line is added before.' file.txt
sed '/pattern/a\This line is added after.' file.txt
```
- Inserts a new line **before** (`i`) or **after** (`a`) the matched pattern.

---

#### **4. Transformations**
**Byte Transformation with `y`:**
```bash
echo "abc" | sed 'y/abc/xyz/'
```
- Transforms `a` to `x`, `b` to `y`, and `c` to `z`.

---

#### **5. Using Ranges**
**Operate on Line Ranges:**
```bash
sed '1,5 s/foo/bar/g' file.txt
```
- Replaces all occurrences of `foo` with `bar` in lines 1 to 5.

**Operate on Multiple Ranges:**
```bash
sed '1,5d;10,15d' file.txt
```
- Deletes lines 1–5 and 10–15.

---

#### **6. Advanced Example with Regular Expressions**
**Add Bullet Points and Format Numbers:**
```bash
sed 's/^\([[:alpha:] ]*\)\([[:digit:]]*\)/=> \1[\2]/g' file.txt
```
- Adds a bullet (`=>`) at the start of each line and encloses numbers in square brackets.

---

#### **7. Use Scripts with `-f`**
**Save Commands in a Script File (`script.sed`):**
```bash
1,3 s/foo/bar/g
/pattern/d
```
**Run the Script:**
```bash
sed -f script.sed file.txt
```
- Executes multiple commands from the script file.

---

### **Practical Applications**
1. **Cleaning Log Files:**  
   Remove blank lines or trailing whitespaces:  
   ```bash
   sed '/^$/d' log.txt
   sed 's/[ \t]*$//' log.txt
   ```

2. **Quick Inline Edits:**  
   Edit files directly:  
   ```bash
   sed -i 's/old/new/g' file.txt
   ```
   *(Adds changes directly to the file.)*

3. **Regex Power:**  
   Combine sed with regex for complex transformations:  
   ```bash
   sed 's/^\([A-Za-z]*\) [0-9]/\1: [NUMBER]/g' file.txt
   ```

---

### **Notes**
- Always test sed commands before using `-i` (in-place edits).
- For complex tasks, combine `sed` with `awk` or scripts for better control.
- Refer to `man sed` for an exhaustive list of features and options.  

With **`sed`**, your creativity is the limit!
