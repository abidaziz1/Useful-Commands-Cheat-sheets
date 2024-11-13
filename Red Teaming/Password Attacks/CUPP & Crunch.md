
---

## CUPP Cheatsheet

### CUPP Basics
CUPP (Common User Passwords Profiler) is a tool for creating customized password lists based on known user information.

#### Basic Command:
```bash
cupp -i
```
- **Purpose**: Starts an interactive session to create a custom password list by asking questions about the target (name, birth date, etc.).

#### Example:
Input the following for a sample user:
- **Name**: `john`
- **Surname**: `doe`
- **Nickname**: `johnny`
- **Birthdate**: `1990`

Result: Generates combinations like `john1990`, `doe1990`, `johnnydoe`, etc.

### Generating Passwords Using a File:
```bash
cupp -w /path/to/input_file.txt
```
- **Purpose**: Generate a password list based on words in `input_file.txt`.

### Generate Common Passwords for a Specific Word:
```bash
cupp -w targetname
```
- **Example**:
   ```bash
   cupp -w john
   ```
   Generates combinations like `john123`, `john@2023`, etc.

### Use a Popular Passwords List:
```bash
cupp -l
```
- **Purpose**: Uses a built-in list of common passwords for quick brute-forcing.

### Custom Password Strength with CUPP:
```bash
cupp -i -o advanced_pw_list.txt
```
- **Purpose**: Export the generated list with custom inputs and save it as `advanced_pw_list.txt`.

---

## Crunch Cheatsheet

Crunch generates wordlists based on specific rules, useful for brute-force and dictionary attacks.

### Basic Syntax:
```bash
crunch <min> <max> <characters> -o <output_file>
```
- **`<min>`**: Minimum length of passwords.
- **`<max>`**: Maximum length of passwords.
- **`<characters>`**: Set of characters to use.
- **`-o <output_file>`**: Specifies output file.

### Examples:

#### Simple List with Specific Length:
```bash
crunch 4 6 abcdef -o list.txt
```
- Generates words from 4 to 6 characters using `a, b, c, d, e, f`.

#### Generate Only Lowercase Passwords:
```bash
crunch 5 8 abcdefghijklmnopqrstuvwxyz -o lowercase.txt
```
- **Purpose**: Creates passwords 5 to 8 characters long, only using lowercase letters.

#### Adding Numbers to Passwords:
```bash
crunch 6 6 abc123 -o alphanum.txt
```
- Generates a 6-character wordlist with both letters and numbers.

#### Adding Symbols:
```bash
crunch 6 8 abcdef123!@# -o symbols.txt
```
- Generates words from 6 to 8 characters long with letters, numbers, and symbols.

### Crunch Patterns

Crunch supports patterns where `@` is a lowercase letter, `,` is an uppercase letter, `%` is a number.

#### Pattern Example:
```bash
crunch 8 8 -t @@@123!! -o pattern.txt
```
- **Pattern**: Generates 8-character passwords like `abc123!!`.

#### Combine Letters, Symbols, and Numbers:
```bash
crunch 8 8 -t @@12@@!! -o complex.txt
```
- Generates words like `ab12cd!!`, mixing letters, numbers, and symbols.

#### Patterns with Specific Symbols:
```bash
crunch 10 10 -t @@%%abcd%% -o specific_symbols.txt
```
- Generates 10-character passwords with 2 lowercase letters, numbers, followed by `abcd`, and more numbers.

### Generating Date-Based Passwords
```bash
crunch 8 8 0123456789 -t 199@-@@ -o dates.txt
```
- **Purpose**: Generates date-based patterns (e.g., `1990-01`).

### Generating Passwords with Common Phrases or Words
Crunch can incorporate specific words/phrases using placeholders.

```bash
crunch 12 12 -t John1234@@ -o john_variants.txt
```
- **Purpose**: Adds two random lowercase letters after "John1234".

### Using a File for Word Variations
```bash
crunch 5 10 -o dictionary_combos.txt -p word1 word2 word3
```
- **Purpose**: Uses each of these words in all possible combinations.

#### Example:
   ```bash
   crunch 5 5 -p dog cat fish
   ```
   Generates combinations like `dogcat`, `catdog`, etc.

---

## Combining CUPP and Crunch Output

You can combine outputs from CUPP and Crunch into a single file using `cat`:
```bash
cat cupp_output.txt crunch_output.txt > combined_password_list.txt
```

## Advanced Customizations with Pipes

### Piping Crunch into Hashcat:
You can use Crunch’s output directly in Hashcat for efficient brute-forcing.

```bash
crunch 8 8 -t @@123@@ | hashcat -m 0 -a 0 target_hash
```
