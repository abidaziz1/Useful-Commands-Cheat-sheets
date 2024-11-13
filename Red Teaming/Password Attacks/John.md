---

### Rule-Based Attacks Overview
Rule-based attacks, or hybrid attacks, apply known password policies to manipulate or "mangle" words in a wordlist to generate potential passwords that fit specific guidelines.

### Common John the Ripper Commands for Rule-Based Attacks

- **Wordlist**: `--wordlist=<path_to_wordlist>` specifies the dictionary to use.
- **Rules**: `--rules=<rule>` specifies which rule(s) to apply.
- **Output**: `--stdout` outputs generated passwords to the terminal without cracking.
- **Count**: `| wc -l` counts the number of generated lines.

---

### Step 1: List Available Rules in john.conf
To see available rules in `john.conf`:
```bash
cat /etc/john/john.conf | grep "List.Rules:" | cut -d"." -f3 | cut -d":" -f2 | cut -d"]" -f1 | awk NF
```

#### Sample Rules Output:
```plaintext
JumboSingle, best64, KoreLogic, d3ad0ne, dive, InsidePro, T9, T0XlC
```

---

### Step 2: Applying Built-In Rules

#### 1. **Best64 Rule** (A common and effective set of 64 rules)
```bash
john --wordlist=/tmp/single-password-list.txt --rules=best64 --stdout | wc -l
```
- **Explanation**: Uses `best64` to apply variations to the password in `/tmp/single-password-list.txt`.
- **Example**: Expands a single password like `tryhackme` to variations such as `TrYhAcKmE`, `tryH@ckMe`, etc.

#### 2. **KoreLogic Rule** (Complex rule for exhaustive mangling)
```bash
john --wordlist=single-password-list.txt --rules=KoreLogic --stdout | grep "Tryh@ckm3"
```
- **Explanation**: Uses KoreLogic to generate advanced combinations and checks for specific passwords like `Tryh@ckm3`.
  
---

### Step 3: Creating Custom Rules

You can add custom rules to `john.conf` to tailor your wordlist expansions.

#### Example Custom Rule for Special Characters and Numbers

1. **Edit john.conf**:
   ```bash
   sudo vi /etc/john/john.conf
   ```
2. **Add Custom Rule**:
   ```plaintext
   [List.Rules:THM-Password-Attacks]
   Az"[0-9]" ^[!@#$]
   ```
   - **Az**: Represents each word from the input list.
   - **"[0-9]"**: Appends a digit (0-9) at the end.
   - **`^[!@#$]`**: Prepends a special character at the start.

3. **Apply Custom Rule to a Wordlist**:
   - **Create Test Wordlist**:
     ```bash
     echo "password" > /tmp/single.lst
     ```
   - **Run John with Custom Rule**:
     ```bash
     john --wordlist=/tmp/single.lst --rules=THM-Password-Attacks --stdout
     ```
     **Output**:
     ```plaintext
     !password0
     @password1
     #password2
     $password3
     ```
   - **Explanation**: Each word in `/tmp/single.lst` is expanded with the rule-defined characters and numbers.

---

### Additional Custom Rule Syntax

- **Append/Prepend Characters**: 
   - **`Az"[0-9]"`**: Appends numbers to the end of words.
   - **`^[!@#$]`**: Adds symbols at the beginning.
   - **`Az"[A-Z]"`**: Adds uppercase letters at the end.

- **Multiple Digits**:
   - **`Az"[0-9][0-9]"`**: Appends two-digit numbers (00 to 99) at the end of each word.

- **Combining Rules**:
   - You can create multiple rules in `[List.Rules:YourRuleName]` and apply all at once.

---

### Rule Application Examples

#### Using `Single` Rule
```bash
john --wordlist=custom-list.txt --rules=Single --stdout
```
- **Explanation**: Applies the `Single` rule for common word mangling, e.g., replacing `o` with `0` or `e` with `3`.

#### Using Multiple Rules Together
```bash
john --wordlist=custom-list.txt --rules=best64 --rules=KoreLogic --stdout
```
- **Explanation**: Combines `best64` and `KoreLogic` to maximize wordlist generation from `custom-list.txt`.

---

### Combining Custom Rules with Built-In Rules

You can run a rule-based attack with custom rules and predefined rules:

```bash
john --wordlist=custom-list.txt --rules=THM-Password-Attacks --rules=best64 --stdout
```

- **Explanation**: Expands `custom-list.txt` using both `THM-Password-Attacks` and `best64` rules for complex variations.

---
Here's an expanded **John the Ripper** cheatsheet with more advanced commands and examples for rule-based attacks, covering a wider range of usage scenarios.

---

### Rule-Based Attack Essentials

John the Ripper’s rule-based attacks are powerful and flexible. Here’s a breakdown of commands for setting up complex rule-based password cracking.

---

### Exploring Built-In Rules with Advanced Commands

1. **List All Available Rules**
   ```bash
   john --list=rules
   ```
   - **Explanation**: Lists all rule sets available within the current John configuration file.

2. **Apply Specific Rule with a Wordlist**
   ```bash
   john --wordlist=wordlist.txt --rules=best64 --stdout
   ```
   - **Explanation**: Uses the `best64` rule on `wordlist.txt` to create variations.
   - **Output Example**: Outputs mangled variations like `Password123`, `P@ssword`, etc.

3. **Testing Rules Output Only**
   ```bash
   john --wordlist=wordlist.txt --rules=KoreLogic --stdout | head -n 20
   ```
   - **Explanation**: Generates the first 20 variations from the KoreLogic rule without performing actual cracking.

4. **Use the Jumbo Rule Set**
   ```bash
   john --wordlist=sample.txt --rules=Jumbo --stdout
   ```
   - **Explanation**: Applies the comprehensive `Jumbo` rule set, which combines multiple rules into one extensive mangling approach.

5. **Apply Multiple Rules in Sequence**
   ```bash
   john --wordlist=sample.txt --rules=best64 --rules=Single --stdout
   ```
   - **Explanation**: First applies `best64` rules, then `Single` rules to generate even more variations.

---

### Rule-Based Attack with Custom Rules

1. **Defining Custom Rules in john.conf**
   - Open the configuration file:
     ```bash
     sudo vi /etc/john/john.conf
     ```
   - Add custom rules under a unique header, such as:
     ```plaintext
     [List.Rules:CustomRules]
     Az"[0-9]" ^[!@#$]
     ```

2. **Running John with Custom Rules**
   ```bash
   john --wordlist=mywordlist.txt --rules=CustomRules --stdout
   ```
   - **Explanation**: Uses `CustomRules` to generate wordlist variations based on special character and number requirements.

3. **Create a Custom Rule for Capitalization and Numbers**
   ```plaintext
   [List.Rules:CapAndNum]
   Az"[0-9]" c
   ```
   - **Az**: Takes each word from the list.
   - **`[0-9]`**: Appends a digit to the end of each word.
   - **c**: Capitalizes the first letter of each word.

   **Usage**:
   ```bash
   john --wordlist=common_passwords.txt --rules=CapAndNum --stdout
   ```

---

### Combining Word Mangling and Rules

1. **Generate Mixed Case and Symbols**
   ```bash
   john --wordlist=mywordlist.txt --rules=best64 --rules=KoreLogic --stdout
   ```
   - **Explanation**: Combines two rule sets, expanding words from `mywordlist.txt` using both `best64` and `KoreLogic`.

2. **Apply All Possible Rules for Comprehensive Wordlist Generation**
   ```bash
   john --wordlist=mywordlist.txt --rules=All --stdout
   ```
   - **Explanation**: Uses every rule in the configuration to maximize wordlist expansion. Note: This can generate a very large list and is resource-intensive.

3. **Generate with Specific Character Sets**
   ```bash
   john --wordlist=base.txt --rules=ShiftToggle --stdout | grep -E "^[A-Za-z0-9]*$"
   ```
   - **Explanation**: Applies `ShiftToggle` rules and filters for alphanumeric-only results.

---

### Custom Rule Syntax Examples

Here’s how to create custom rules in `john.conf` for specialized wordlist manipulation.

1. **Appending Dates or Years**
   - **Rule**:
     ```plaintext
     Az"[19][80-90]"
     ```
   - **Explanation**: Appends years from 1980 to 1990 to each word.

2. **Adding Symbols at the Start and Digits at the End**
   - **Rule**:
     ```plaintext
     ^[!@#] Az"[0-9]"
     ```
   - **Explanation**: Adds `!`, `@`, or `#` at the start and a digit from `0-9` at the end.

3. **Combining Uppercase with Symbols and Numbers**
   - **Rule**:
     ```plaintext
     Az"123" c ^[!]
     ```
   - **Explanation**: Capitalizes the first letter, appends "123", and adds `!` at the beginning.

---

### Real-World Rule-Based Attack Commands

1. **Using John to Crack NTLM Hashes with Wordlist and Rules**
   ```bash
   john --format=NT --wordlist=common_passes.txt --rules=best64 hash.txt
   ```
   - **Explanation**: Uses `best64` rule to expand `common_passes.txt` and attack NTLM hashes in `hash.txt`.

2. **Using KoreLogic for Windows LM Hashes**
   ```bash
   john --format=LM --wordlist=sample.txt --rules=KoreLogic hashfile.txt
   ```
   - **Explanation**: Uses KoreLogic rule on `sample.txt` to expand it for cracking Windows LM hashes in `hashfile.txt`.

3. **Applying Rules with Masks for Known Patterns**
   ```bash
   john --wordlist=mylist.txt --rules=best64 --mask=?l?u?d?d?l?l --stdout
   ```
   - **Explanation**: Combines `best64` rules with a mask pattern for 7-character passwords (`?l?u?d?d?l?l` - lowercase, uppercase, digit, digit, lowercase, lowercase).

---

### Additional Commands for Managing Output

1. **Redirect Output to File**
   ```bash
   john --wordlist=mylist.txt --rules=KoreLogic --stdout > expanded_list.txt
   ```
   - **Explanation**: Saves expanded wordlist variations to `expanded_list.txt`.

2. **Count Password Variations**
   ```bash
   john --wordlist=mylist.txt --rules=best64 --stdout | wc -l
   ```
   - **Explanation**: Counts the number of generated passwords.

3. **Save Unique Passwords Only**
   ```bash
   john --wordlist=mylist.txt --rules=best64 --stdout | sort | uniq > unique_passwords.txt
   ```
   - **Explanation**: Outputs only unique passwords.

---

### Rule-Based Mask Combination Examples

Using masks with rules helps target specific password patterns:

1. **Rule with Mask for Alpha-Numeric and Symbols**
   ```bash
   john --wordlist=base_words.txt --rules=best64 --mask=?l?u?d?s --stdout
   ```
   - **Explanation**: Generates 4-character passwords with lowercase, uppercase, digit, and symbol.

2. **Rule with Mask for Structured Patterns**
   ```bash
   john --wordlist=base.txt --rules=KoreLogic --mask=?u?l?d?d?l?l?s
   ```
   - **Explanation**: Uses a pattern like `A1b2c@` with uppercase, lowercase, and symbol patterns.

---

### Tips for Effective Rule-Based Attacks

- **Focus on Specific Rules**: Start with smaller, targeted rule sets like `best64` or `Single`.
- **Use Masks for Pattern-Specific Attacks**: Masks narrow down password possibilities.
- **Experiment with Custom Rules**: Modify john.conf with tailored rules based on the target’s password policy.
- **Combine Multiple Rules and Masks**: Apply multiple rules for exhaustive generation if you have sufficient resources.

With these advanced commands, you can fully harness John the Ripper’s rule-based attack capabilities, tailoring password generation to specific policies and patterns for more effective brute-force attempts.
