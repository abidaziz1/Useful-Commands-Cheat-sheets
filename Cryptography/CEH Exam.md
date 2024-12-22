### **Cryptography Concepts and Encryption Algorithms**

#### **What is Cryptography?**
Cryptography is the art and science of securing information through techniques that ensure data confidentiality, integrity, authentication, and nonrepudiation. It involves converting plaintext (readable information) into ciphertext (unreadable data) using encryption algorithms, which can later be decrypted back into plaintext with the appropriate key.

---

### **Objectives of Cryptography**
1. **Confidentiality**: Ensures only authorized entities can access the information.
2. **Integrity**: Protects data from unauthorized modifications.
3. **Authentication**: Verifies the identity of the sender or the origin of the data.
4. **Nonrepudiation**: Prevents denial of actions (e.g., message sent or received).

---

### **Types of Cryptography**

#### 1. **Symmetric Encryption**
- Uses the same key for encryption and decryption.
- **Example**: DES, AES, RC4.
- **Advantages**:
  - Faster and requires less processing power.
  - Suitable for encrypting large amounts of data.
- **Weaknesses**:
  - Requires secure key exchange.
  - Not scalable for large networks.

#### 2. **Asymmetric Encryption**
- Uses a key pair: a public key for encryption and a private key for decryption.
- **Example**: RSA, ECC, DSA.
- **Advantages**:
  - Enhanced security since private keys are never shared.
  - Scalable for Internet-based secure communication.
- **Weaknesses**:
  - Slower than symmetric encryption.
  - Higher processing power requirements.

---

### **Ciphers**
#### **Types of Ciphers**
1. **Classical Ciphers**:
   - Operate on the alphabet (A-Z).
   - **Examples**: Substitution cipher, transposition cipher.
   - Easily broken and not suitable for modern applications.

2. **Modern Ciphers**:
   - Designed for advanced security.
   - **Types**:
     - **Symmetric Key Ciphers**: Same key for encryption/decryption.
     - **Asymmetric Key Ciphers**: Public/private key pair.
     - **Block Ciphers**: Operate on fixed-size data blocks (e.g., AES).
     - **Stream Ciphers**: Encrypt data bit-by-bit (e.g., RC4).

---

### **Symmetric Encryption Algorithms**
| **Algorithm** | **Cipher Type** | **Key Size** | **Block Size** | **Application Areas** |
|---------------|-----------------|--------------|----------------|------------------------|
| DES           | Block           | 56 bits      | 64 bits        | Legacy systems        |
| 3DES          | Block           | 112, 168 bits| 64 bits        | Financial services     |
| AES           | Block           | 128-256 bits | 128 bits       | Secure communications |
| RC4           | Stream          | Variable     | -              | Web traffic encryption|
| RC5           | Block           | Variable     | Variable       | Cryptographic libraries|
| RC6           | Block           | 128-256 bits | 128 bits       | Advanced encryption    |
| Blowfish      | Block           | 32-448 bits  | 64 bits        | Secure storage        |

#### **Notable Symmetric Algorithms**
1. **Data Encryption Standard (DES)**:
   - 64-bit blocks with a 56-bit key.
   - Vulnerable to modern brute-force attacks; superseded by AES and 3DES.

2. **Triple DES (3DES)**:
   - Applies DES encryption three times for added security.
   - Uses three keys: K1, K2, K3 (optionally, K1 = K3 for less security).

3. **Advanced Encryption Standard (AES)**:
   - 128-bit block size with key lengths of 128, 192, or 256 bits.
   - Highly secure and efficient for both hardware and software applications.

---

### **Key Cryptographic Concepts**

#### **Government Access to Keys (GAK)**
- **Definition**: A statutory requirement for organizations to share cryptographic keys with government agencies for lawful interception.
- **Concerns**:
  - Privacy and security risks.
  - Potential misuse of keys.

#### **Key Escrow**
- Third-party storage of cryptographic keys, allowing access under predefined conditions (e.g., court order).

---

### **Strengths and Weaknesses of Cryptography**

| **Encryption Type**  | **Strengths**                                      | **Weaknesses**                                     |
|-----------------------|---------------------------------------------------|---------------------------------------------------|
| Symmetric             | Fast, efficient, requires less processing power   | Key exchange and management challenges            |
| Asymmetric            | No need to share private keys, supports scalability | Slower, requires more computational resources     |

---

### **Modern Cipher Types**

#### **Block Ciphers**
- Operate on fixed-sized blocks of data.
- Examples: AES, DES, Blowfish.

#### **Stream Ciphers**
- Encrypt data one bit at a time.
- Examples: RC4, ChaCha20.

---

### **Applications of Cryptography**
- **Secure Communications**: E.g., email encryption, SSL/TLS.
- **Authentication**: Digital signatures, certificates.
- **Data Integrity**: Hash functions like SHA.
- **Secure Storage**: Disk encryption, cloud security.

---

### **RC4, RC5, and RC6 Algorithms**

#### **RC4 (Rivest Cipher 4)**
- **Type**: Stream cipher.
- **Key Size**: Variable (40 to 2048 bits).
- **Features**:
  - Byte-oriented with random permutation.
  - Fast and efficient, ideal for software implementation.
  - Used in SSL, TLS, and Wi-Fi security (WEP/WPA).
- **Weaknesses**:
  - Vulnerabilities when used improperly (e.g., weak key scheduling in WEP).

---

#### **RC5**
- **Type**: Block cipher.
- **Key Size**: Variable (0 to 2040 bits).
- **Block Size**: 32, 64, or 128 bits.
- **Rounds**: Variable (0 to 255).
- **Features**:
  - Flexible configuration for block size, key size, and rounds.
  - Combines addition, XOR, and data-dependent rotations.
  - Secure against cryptanalysis due to intensive data-dependent operations.

---

#### **RC6**
- **Type**: Block cipher (derived from RC5).
- **Key Size**: 128, 192, or 256 bits.
- **Block Size**: 128 bits.
- **Rounds**: Variable.
- **Features**:
  - Introduces integer multiplication for enhanced diffusion.
  - Uses four 4-bit working registers for AES compatibility.
  - Faster and more secure than RC5.

---

### **Blowfish**
- **Type**: Symmetric block cipher.
- **Key Size**: 32 to 448 bits.
- **Block Size**: 64 bits.
- **Features**:
  - Designed to replace DES.
  - Efficient and fast for software encryption.
  - 16-round Feistel cipher with complex key expansion.
- **Applications**: Password protection, e-commerce security.

---

### **Twofish**
- **Type**: Symmetric block cipher.
- **Key Size**: Up to 256 bits.
- **Block Size**: 128 bits.
- **Features**:
  - Flexible performance trade-offs (speed, memory usage).
  - Optimized for both hardware and software.
  - High security but slower than AES in some cases.

---

### **Threefish**
- **Type**: Symmetric block cipher.
- **Key Sizes**: 256, 512, and 1024 bits.
- **Block Sizes**: 256, 512, and 1024 bits.
- **Rounds**: 72 for smaller blocks, 80 for 1024-bit blocks.
- **Features**:
  - ARX (Addition, Rotation, XOR) operations for simplicity.
  - Resistant to cache-timing attacks due to the absence of S-boxes.

---

### **Serpent**
- **Type**: Symmetric block cipher.
- **Key Sizes**: 128, 192, and 256 bits.
- **Block Size**: 128 bits.
- **Features**:
  - 32 computational rounds for high security.
  - Designed for software and hardware implementation.
  - More secure but slower than AES.

---

### **TEA (Tiny Encryption Algorithm)**
- **Type**: Feistel cipher.
- **Key Size**: 128 bits.
- **Block Size**: 64 bits.
- **Rounds**: 64 (or configurable).
- **Features**:
  - Simple and lightweight.
  - Uses addition and subtraction modulo \(2^{32}\) for encryption.

---

### **CAST-128 and CAST-256**
- **CAST-128**:
  - Block Size: 64 bits.
  - Key Size: 40 to 128 bits.
  - Features large S-boxes and modular arithmetic.
- **CAST-256**:
  - Block Size: 128 bits.
  - Key Size: 128 to 256 bits.
  - Extension of CAST-128 with enhanced security.

---

### **GOST Block Cipher**
- **Key Size**: 256 bits.
- **Block Size**: 64 bits.
- **Features**:
  - 32-round Feistel network.
  - Secret S-box for enhanced security.
  - Latest variant, Kuznyechik, uses 128-bit blocks.

---

### **Camellia**
- **Key Sizes**: 128, 192, or 256 bits.
- **Block Size**: 128 bits.
- **Rounds**: 18 for 128-bit keys, 24 for longer keys.
- **Features**:
  - Highly secure with key whitening.
  - Used in TLS for secure communication.

---

### **Asymmetric Encryption Algorithms**

| **Algorithm**              | **Key Size**       | **Applications**                  |
|----------------------------|--------------------|------------------------------------|
| RSA                        | Variable           | Encryption, digital signatures    |
| Digital Signature Algorithm (DSA) | Variable           | Digital signatures                |
| Diffie-Hellman             | Variable           | Key exchange                      |
| Elliptic Curve Cryptography (ECC) | 160–521 bits       | Secure communication, encryption |
| ElGamal                    | Variable           | Encryption, key exchange          |

---

### **RSA (Rivest-Shamir-Adleman)**
- **Type**: Asymmetric encryption.
- **Key Generation**:
  - Choose two large primes \(p\) and \(q\).
  - Compute \(n = pq\) and \(\phi(n) = (p-1)(q-1)\).
  - Select public key \(e\) such that \(1 < e < \phi(n)\) and \(\text{gcd}(e, \phi(n)) = 1\).
  - Compute private key \(d\) such that \(ed \equiv 1 \mod \phi(n)\).
- **Encryption**: \(C = M^e \mod n\).
- **Decryption**: \(M = C^d \mod n\).
- **Applications**: Secure key exchange, digital signatures.

---

### **Digital Signature Algorithm (DSA)**
- **Purpose**: Used for signing and verifying digital messages.
- **Key Generation**:
  - Generate public/private key pair.
  - Public key: \( (p, q, \alpha, y) \).
  - Private key: \( d \).
- **Signing**:
  - Create signature \((r, s)\) using private key.
- **Verification**:
  - Validate signature using public key.

---
### **Diffie–Hellman Algorithm**

#### **Overview**:
- **Purpose**: Establishes a shared secret key between two parties over an insecure channel.
- **Developers**: Whitfield Diffie and Martin Hellman (1976), with earlier classified work by Malcolm J. Williamson.
- **Core Concept**:
  - Uses mathematical properties of modular arithmetic.
  - Lacks authentication, making it vulnerable to man-in-the-middle attacks.

#### **Steps**:
1. **Parameters**:
   - \( p \): A large prime number.
   - \( g \): A generator, where \( 1 \leq g < p \) and every number \( n \) between \( 1 \) and \( p-1 \) can be expressed as \( g^k \mod p \) for some \( k \).

2. **Private and Public Values**:
   - Alice selects a random private value \( a \), computes \( g^a \mod p \), and shares this as her public value.
   - Bob selects a random private value \( b \), computes \( g^b \mod p \), and shares this as his public value.

3. **Key Exchange**:
   - Alice receives Bob's public value \( g^b \mod p \) and computes the shared key: \( (g^b)^a \mod p = g^{ab} \mod p \).
   - Bob receives Alice's public value \( g^a \mod p \) and computes the shared key: \( (g^a)^b \mod p = g^{ab} \mod p \).

4. **Result**:
   - Both parties derive the same shared secret \( g^{ab} \mod p \), which can be used as a symmetric encryption key.

---

### **Elliptic Curve Cryptography (ECC)**

#### **Overview**:
- **Purpose**: Provides encryption with smaller key sizes compared to RSA.
- **Core Concept**:
  - Relies on elliptic curves over finite fields.
  - Uses the mathematical difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

#### **Benefits**:
- Smaller keys provide equivalent security (e.g., 256-bit ECC ≈ 3072-bit RSA).
- Faster encryption and decryption due to reduced computational overhead.
- Lower power consumption, suitable for mobile and IoT devices.

---

### **YAK Protocol**

#### **Overview**:
- **Type**: Public-key-based authenticated key exchange (AKE) protocol.
- **Purpose**: Secure exchange of session keys with public key authentication.
- **Steps**:
  1. Both parties generate random numbers, compute values based on them, and send Zero-Knowledge Proofs (ZKP) to verify the ownership of private keys.
  2. Session keys are computed and authenticated.
  3. Both parties obtain the same session key securely.

#### **Advantages**:
- Private key security.
- Session key security.
- Forward secrecy.

---

### **Message Digest (Hash) Functions**

#### **Overview**:
- **Purpose**: Generate a fixed-size hash value from arbitrary input data to ensure data integrity.
- **Properties**:
  - **One-way**: Irreversible.
  - **Collision-resistant**: Hard to find two inputs with the same hash.
  - **Deterministic**: Same input always produces the same output.
  - **Fast**: Efficient to compute.

#### **Applications**:
- Digital signatures.
- Message authentication codes (MACs).
- File integrity verification.

---

### **Common Hash Functions**

| Algorithm | Output Size | Block Size | Security Level | Applications                       |
|-----------|-------------|------------|----------------|------------------------------------|
| MD5       | 128 bits    | 512 bits   | Weak           | Legacy systems, checksum validation |
| SHA-1     | 160 bits    | 512 bits   | Weak           | TLS, SSL (deprecated)             |
| SHA-2     | 224–512 bits| 512 bits   | Strong         | Secure communication, signatures  |
| SHA-3     | 224–512 bits| Variable   | Strong         | Advanced cryptography             |

---

### **MD5 vs SHA**
- **MD5**:
  - Fast but vulnerable to collision attacks.
  - Outputs 128-bit hashes.
- **SHA-2**:
  - More secure, supports larger hashes (e.g., 256-bit, 512-bit).
  - Recommended for modern cryptographic applications.

---

### **Multilayer Hashing**
- **Concept**: Applies multiple hash functions sequentially to increase complexity.
- **Benefits**:
  - Enhances security against brute-force attacks.
  - Adds additional layers of obfuscation.
- **Tool Example**: CyberChef.

---

### **HMAC (Hash-based Message Authentication Code)**

#### **Overview**:
- Combines a cryptographic hash function (e.g., SHA-2) with a secret key.
- Used for verifying message integrity and authenticity.

#### **Process**:
1. Split the key into inner and outer keys.
2. Compute the inner hash with the inner key and message.
3. Compute the outer hash with the outer key and the inner hash result.

#### **Advantages**:
- Resistant to length-extension attacks.
- Provides strong data integrity and authentication.

---
### **Hardware-Based Encryption**

#### **Overview**
- Uses hardware to assist or replace software in the data encryption process.
- Relieves system resources, providing faster processing and enhanced security.
- Stores encryption keys securely, preventing unauthorized access.
- Hardware encryption is tamper-resistant and blocks unauthorized code execution.

#### **Advantages**
- **Speed**: Faster encryption and decryption processes.
- **Security**: Resistant to software-based attacks and malware.
- **Efficiency**: Frees up CPU and memory for other tasks.

#### **Types of Hardware-Based Encryption Devices**
1. **Trusted Platform Module (TPM)**
   - A cryptographic chip integrated into the motherboard.
   - Provides secure storage for encryption keys.
   - Applications:
     - Full disk encryption (e.g., BitLocker).
     - Password protection.
     - Platform integrity verification.

2. **Hardware Security Module (HSM)**
   - An external device for managing cryptographic keys.
   - Supports secure key storage and high-performance encryption.
   - Examples: Thales Luna HSM, nShield HSM.

3. **USB Encryption**
   - Provides onboard encryption for USB storage devices.
   - Examples: Kingston IronKey, diskAshur Pro.

4. **Hard Drive Encryption**
   - Encrypts data on hardware storage devices.
   - Uses technologies like AES-256.
   - Examples: Military-grade AES encryption drives.

---

### **Quantum Cryptography**

#### **Overview**
- Based on quantum mechanics principles, ensuring unbreakable encryption.
- Uses photons to represent binary data (0s and 1s).

#### **Key Features**
- **Photon Polarization**:
  - Horizontal (—): 0.
  - Vertical (|): 1.
  - Backslash (/): 1.
  - Forward slash (\): 0.
- **Security**:
  - Eavesdropping alters photon polarization, alerting the receiver.
- **Applications**:
  - Quantum Key Distribution (QKD) for secure communication.

---

### **Other Encryption Techniques**

1. **Homomorphic Encryption**
   - Allows data to remain encrypted during processing.
   - Enables mathematical operations on ciphertext.
   - Applications:
     - Secure cloud computing.
     - Privacy-preserving data analysis.

2. **Post-Quantum Cryptography**
   - Resistant to attacks by quantum computers.
   - Designed to replace vulnerable public-key cryptosystems.
   - Applications:
     - Secure e-voting.
     - Future-proof encryption protocols.

3. **Lightweight Cryptography**
   - Optimized for low-powered devices (e.g., IoT, RFID tags).
   - Focuses on minimal resource usage without compromising security.

---

### **Cipher Modes of Operation**

#### **Overview**
- Modes define how a block cipher encrypts/decrypts data.
- Ensure data confidentiality and integrity.

#### **Block Cipher Modes**
1. **Electronic Code Book (ECB)**:
   - Simplest mode; each block is encrypted independently.
   - **Flaw**: Identical plaintext blocks produce identical ciphertext blocks.

2. **Cipher Block Chaining (CBC)**:
   - Each block is XORed with the previous ciphertext block before encryption.
   - **Flaw**: Error propagation.

3. **Cipher Feedback (CFB)**:
   - Ciphertext from previous blocks used as input for encryption.
   - **Advantage**: Resists cryptanalysis due to shift registers.

4. **Counter (CTR)**:
   - Uses a counter value for each block.
   - **Advantage**: No error propagation; parallelizable.

---

### **Authenticated Encryption**

#### **Overview**
- Combines encryption with integrity checks to prevent tampering and chosen ciphertext attacks.

#### **Modes**
1. **Encrypt-then-MAC (EtM)**:
   - Most secure.
   - Encrypts plaintext, then generates a MAC for the ciphertext.

2. **Encrypt-and-MAC (E&M)**:
   - Generates a MAC for plaintext, then encrypts plaintext.

3. **MAC-then-Encrypt (MtE)**:
   - Generates a MAC for plaintext, then combines and encrypts both.

#### **Authenticated Encryption with Associated Data (AEAD)**
- Ensures integrity of both encrypted and unencrypted data.
- Keeps headers unencrypted for verification, while encrypting the payload.

---

### **Cryptography Tools**

#### **BCTextEncoder**
- **Source**: [Jetico](https://www.jetico.com)
- Encodes, compresses, and encrypts text data.
- Supports public key and password-based encryption.
- Uses strong symmetric and public-key algorithms for secure text encoding.

#### **Additional Tools**
- **CryptoForge** ([Website](https://www.cryptoforge.com)): Provides file encryption and secure deletion.
- **AxCrypt** ([Website](https://axcrypt.net)): Simplified file encryption for individuals and teams.
- **Microsoft Cryptography Tools** ([Website](https://www.microsoft.com)): Built-in tools for encrypting data on Windows systems.
- **Concealer** ([Website](https://www.belightsoft.com)): Secures sensitive files and information.
- **SensiGuard** ([Website](https://www.sensiguard.com)): Focuses on file and folder encryption.
- **Cypherix** ([Website](https://www.cypherix.com)): Offers robust encryption for files and drives.

---

### **Applications of Cryptography**

1. **Digital Signatures**
   - Provides authentication and integrity for digital messages.
   - Prevents repudiation by verifying the sender’s identity.

2. **Secure Sockets Layer (SSL) and Transport Layer Security (TLS)**
   - Ensures secure communication over the Internet.
   - SSL/TLS encrypts data transmitted between client and server.
   - Provides private, authenticated, and reliable channels.

3. **Pretty Good Privacy (PGP)**
   - Encrypts emails, files, and directories.
   - Combines data compression, symmetric encryption, and public key cryptography.

4. **Email Encryption**
   - Secures email communication to prevent unauthorized access.
   - Uses protocols like S/MIME or PGP for encryption.

5. **Disk Encryption**
   - Encrypts the entire disk to protect data at rest.
   - Examples: BitLocker, VeraCrypt.

6. **Blockchain**
   - Uses cryptographic hashing and digital signatures for securing transactions.
   - Ensures immutability and integrity of the data.

---

### **Public Key Infrastructure (PKI)**

#### **Overview**
- Security framework for managing digital certificates and public-key encryption.
- Facilitates secure exchange of information over the Internet.

#### **Components**
1. **Certificate Management System**: Manages digital certificates.
2. **Digital Certificates**: Binds public keys to user identities.
3. **Validation Authority (VA)**: Verifies certificate validity.
4. **Certification Authority (CA)**: Issues and verifies certificates.
5. **End User**: Requests and uses certificates.
6. **Registration Authority (RA)**: Authenticates the subject requesting a certificate.

#### **Process**
1. User requests a certificate from RA.
2. RA verifies identity and forwards the request to CA.
3. CA issues a certificate and updates VA.
4. User encrypts or signs messages with a private key.
5. Receiver verifies the certificate via VA.

---

### **Certification Authorities**

#### **Popular CAs**
1. **Comodo** ([Website](https://www.comodoca.com))
   - Offers PKI management and SSL encryption solutions.
   - Includes Comodo Certificate Manager for centralized certificate handling.

2. **IdenTrust** ([Website](https://www.identrust.com))
   - Provides CA services for sectors like banking and healthcare.
   - Supports NIST compliance and managed PKI hosting.

3. **DigiCert CertCentral** ([Website](https://www.digicert.com))
   - Simplifies lifecycle management of TLS/SSL certificates.
   - Centralized control for high-volume issuance.

4. **GoDaddy** ([Website](https://www.godaddy.com))
   - Offers SHA-2 and 2048-bit encrypted SSL certificates.
   - Supports unlimited servers and CA/Browser Forum guidelines.

---

### **Digital Signatures**

#### **Key Features**
- Uses asymmetric cryptography for secure digital authentication.
- Components:
  - **Private Key**: Used to create the digital signature.
  - **Public Key**: Verifies the digital signature.

#### **Process**
1. Sender generates a hash of the message.
2. The hash is encrypted with the sender’s private key to create the digital signature.
3. Receiver uses the sender’s public key to decrypt the signature and verify the hash.

---

### **Secure Sockets Layer (SSL)**

#### **Overview**
- Developed by Netscape for securing Internet communications.
- Uses RSA encryption for securing data during transmission.

#### **SSL Handshake Protocol**
1. **Client Hello**: Client initiates the handshake with a message to the server.
2. **Server Hello**: Server responds with its certificate and cryptographic parameters.
3. **Key Exchange**: Client and server exchange keys to establish a shared secret.
4. **Cipher Spec Change**: Both sides agree on encryption algorithms and keys.
5. **Application Data Exchange**: Secure communication begins.

#### **Session Resumption**
- Allows re-establishing previous sessions to avoid repeating the full handshake process.

---

### **Signed vs. Self-Signed Certificates**

1. **Signed Certificate**
   - Issued by a trusted CA.
   - Validated by querying the validation authority.

2. **Self-Signed Certificate**
   - Generated by the user.
   - Validated manually by the receiver.
   - Not ideal for public-facing applications due to trust issues.

---
### **Transport Layer Security (TLS)**

#### **Overview**
TLS is a cryptographic protocol that provides secure communication over a network. It ensures:
- **Privacy**: Data is encrypted using symmetric keys.
- **Integrity**: Message authentication codes (MACs) validate the integrity of messages.
- **Authentication**: Uses asymmetric cryptography for key exchange and authentication.

#### **Components**
1. **TLS Record Protocol**
   - Provides data fragmentation, compression, encryption, and integrity checks.
   - Ensures connection privacy and reliability using encryption (e.g., DES) and secure hashing (e.g., SHA, MD5).
   - Interacts with the TCP layer to transport data.

2. **TLS Handshake Protocol**
   - Authenticates peers and negotiates encryption algorithms and session keys.
   - Uses asymmetric cryptography for initial key exchange and symmetric keys for bulk data encryption.

#### **TLS Handshake Process**
1. **Client Hello**:
   - Client sends a message with supported cipher suites and a random value.
2. **Server Hello**:
   - Server responds with selected cipher suite and its random value.
   - Server sends its certificate and optionally requests the client’s certificate.
3. **Key Exchange**:
   - Client sends an encrypted pre-master secret using the server’s public key.
   - Both client and server compute the master secret and session keys.
4. **Change Cipher Spec**:
   - Client and server switch to encrypted communication using the negotiated session keys.
5. **Finished Messages**:
   - Both parties confirm the handshake's success.
6. **Secure Communication**:
   - Application data is exchanged over the encrypted channel.

---

### **Cryptography Toolkits**

1. **OpenSSL**  
   - Source: [OpenSSL](https://www.openssl.org)  
   - Open-source toolkit for SSL/TLS and cryptography standards.  
   - Functions:
     - Create and manage keys and certificates.
     - Perform public-key operations.
     - Generate certificate signing requests (CSRs) and revocation lists (CRLs).  

2. **Other Toolkits**
   - **wolfSSL**: Lightweight SSL/TLS library for IoT and embedded systems.  
   - **AES Crypto Toolkit**: National Instruments’ AES implementation for secure applications.  
   - **Libsodium**: Modern and easy-to-use library for encryption, signatures, and more.  
   - **Crypto++**: Comprehensive library for various cryptographic algorithms.  
   - **PyCryptodome**: Python library for implementing cryptographic primitives.

---

### **Pretty Good Privacy (PGP)**

#### **Key Features**
- **Hybrid Encryption**: Combines public-key and symmetric-key cryptography.
- **Use Cases**:
  - Encrypt and sign messages and files.
  - Compress data to enhance security and reduce storage.
  - Ensure email privacy and authenticity.

#### **PGP Workflow**
1. **Encryption**:
   - Data is compressed and encrypted with a random symmetric key.
   - The symmetric key is encrypted with the recipient's public key and sent with the ciphertext.
2. **Decryption**:
   - Recipient decrypts the symmetric key using their private key.
   - Decrypts the ciphertext using the symmetric key.

#### **GNU Privacy Guard (GPG)**
- Open-source implementation of PGP.
- Supports modern cryptographic algorithms like ECC.
- Functions:
  - Manage keys and certificates.
  - Encrypt and sign files.
  - Secure messaging applications.

---

### **Web of Trust (WOT)**

#### **Concept**
- A decentralized model for verifying public key authenticity.
- Users sign each other’s public keys, creating a network of trust.

#### **How It Works**
1. Users maintain a keyring of trusted public keys.
2. Keys are signed by others in the network, verifying their authenticity.
3. Communication is encrypted using the recipient’s public key and signed with the sender’s private key.

---

### **Encrypting Email Messages**

#### **S/MIME (Secure/Multipurpose Internet Mail Extensions)**
- Encrypts and digitally signs emails.
- Uses certificates for sender and recipient authentication.

#### **Microsoft 365 Message Encryption**
1. Enable encryption through the message options menu.
2. Apply constraints like "Encrypt-Only" or "Do Not Forward."
3. Authenticate recipients with Microsoft accounts or one-time passwords.

#### **OpenPGP Encryption**
- Combines public and private keys for email security.
- Tools like **FlowCrypt** integrate OpenPGP into email clients.

---

### **FlowCrypt for Gmail**
1. **At the Sender’s End**:
   - Compose a secure message using the FlowCrypt browser extension.
   - Encrypt the message with the recipient’s public key and send it.
2. **At the Recipient’s End**:
   - Decrypt the message using their private key.
   - Verify the sender's signature for authenticity.

---

### **Email Encryption Tools**

#### **Popular Email Encryption Tools**
1. **RMail**
   - Source: [RMail](https://rmail.com)
   - Features: Email encryption, open tracking, delivery proof, electronic signatures, large file transfer.
   - Integrates seamlessly with platforms like Microsoft Outlook and Gmail.

2. **Mailvelope**
   - Source: [Mailvelope](https://mailvelope.com)
   - Browser-based encryption for webmail clients like Gmail, Yahoo, and Outlook.
   - OpenPGP-based encryption for secure email communication.

3. **Virtru**
   - Source: [Virtru](https://www.virtru.com)
   - Simplified encryption for Gmail and Outlook.
   - Features: Secure file sharing, audit tracking, and granular access control.

4. **Webroot™ Email Encryption**
   - Source: [Webroot](https://www.webroot.com)
   - Protects email data in transit and at rest using strong encryption standards.

5. **Secure Email (S/MIME) Certificates**
   - Source: [SSL.com](https://www.ssl.com)
   - Provides certificates for digitally signing and encrypting emails.

6. **Proofpoint Email Protection**
   - Source: [Proofpoint](https://www.proofpoint.com)
   - Combines email encryption with advanced threat protection.

7. **Paubox**
   - Source: [Paubox](https://www.paubox.com)
   - HIPAA-compliant email encryption tailored for healthcare organizations.

---

### **Disk Encryption**

#### **Purpose**
Disk encryption secures all data on a disk by converting it into unreadable code. It ensures confidentiality and privacy, even if the storage device is compromised.

#### **Popular Disk Encryption Tools**

1. **VeraCrypt**
   - Source: [VeraCrypt](https://veracrypt.fr)
   - Features: On-the-fly encryption for volumes, hidden volumes, support for multiple operating systems.
   - Supports AES, Serpent, and Twofish encryption algorithms.

2. **Rohos Disk Encryption**
   - Source: [Rohos](https://rohos.com)
   - Features: Creates encrypted partitions on computers, USBs, or cloud storage.
   - Uses AES-256 encryption.

3. **BitLocker Drive Encryption**
   - Source: [Microsoft](https://www.microsoft.com)
   - Built-in for Windows; encrypts entire disk volumes.
   - Uses Trusted Platform Module (TPM) for enhanced security.

4. **Symantec Encryption**
   - Source: [Broadcom](https://www.broadcom.com)
   - Enterprise-grade disk encryption solution.
   - Features: Full-disk encryption, key management, and policy-based enforcement.

5. **GiliSoft Full Disk Encryption**
   - Source: [GiliSoft](https://www.gilisoft.com)
   - Simple, lightweight encryption for personal and business use.

6. **DiskCryptor**
   - Source: [DiskCryptor](https://diskcryptor.org)
   - Open-source disk encryption tool supporting full disk and external storage encryption.

#### **Disk Encryption Tools for Linux**
- **Cryptsetup**: Utility for managing dm-crypt encrypted volumes.
- **Cryptmount**: Tool for creating and managing encrypted file systems.
- **Tomb**: CLI-based encryption tool for Linux.
- **CryFS**: Encrypts files for cloud storage.
- **GnuPG**: Encryption for files and email messages.

#### **Disk Encryption Tools for macOS**
- **FileVault**: Built-in disk encryption for macOS, using XTS-AES-128 with a 256-bit key.
- **BestCrypt Volume Encryption**: Cross-platform encryption software.
- **Comodo Disk Encryption**: Secure disk encryption for macOS users.

---

### **Blockchain**

#### **Key Features**
- Blockchain is a secure, distributed ledger technology.
- Maintains transparency and immutability through cryptographic techniques.

#### **Types of Blockchain**
1. **Public Blockchain**:
   - Decentralized and permissionless.
   - Examples: Bitcoin, Ethereum.

2. **Private Blockchain**:
   - Centralized with restricted access.
   - Examples: Hyperledger, Ripple (XRP).

3. **Consortium Blockchain**:
   - Semi-decentralized, controlled by a group.
   - Examples: R3 (banking), EWF (energy).

4. **Hybrid Blockchain**:
   - Combines public and private blockchain characteristics.
   - Example: IBM Food Trust.

#### **Security Mechanisms**
- **Hashing**: Secure transaction validation (e.g., SHA-256).
- **Proof of Work (PoW)**: Ensures block legitimacy and prevents tampering.

---

### **Cryptanalysis**

#### **Techniques**

1. **Linear Cryptanalysis**
   - Identifies linear approximations of cipher operations.
   - Useful for breaking block ciphers like DES.

2. **Differential Cryptanalysis**
   - Analyzes input-output differences to uncover keys.
   - Effective against symmetric-key ciphers.

3. **Integral Cryptanalysis**
   - Extends differential techniques for substitution-permutation networks.
   - Efficient for analyzing block ciphers.

4. **Quantum Cryptanalysis**
   - Utilizes quantum algorithms to compromise classical cryptographic systems.
   - Algorithms like Shor’s and Grover’s can factor RSA keys and speed up brute-force attacks.

#### **Quantum Cryptanalysis Resources**
- Circuit width and depth.
- Number of quantum gates (e.g., T-gates).

### **Cryptography Attacks**

#### **1. Ciphertext-only Attack**
- **Description:** The attacker only has access to the ciphertext and attempts to deduce the plaintext or key.
- **Likelihood:** High, as ciphertext is more accessible.
- **Effectiveness:** Low, as it is the most challenging due to limited information.

#### **2. Adaptive Chosen-plaintext Attack**
- **Description:** The attacker chooses plaintext messages and modifies them based on the results of previous encryptions.
- **Requirement:** Interaction with the encryption device.

#### **3. Chosen-plaintext Attack**
- **Description:** The attacker can encrypt plaintext of their choosing to gather insights into the encryption key.
- **Effectiveness:** High, especially when the attacker gains access to the encryption algorithm.

#### **4. Related-Key Attack**
- **Description:** Targets systems where the keys are related (e.g., derived from a master key). The attacker analyzes the relationship between plaintext and ciphertext under different keys.

#### **5. Dictionary Attack**
- **Description:** The attacker precomputes a dictionary of plaintext-ciphertext pairs to match future ciphertext with a known plaintext.
- **Common Use:** Cracking passwords and passphrases.

#### **6. Known-plaintext Attack**
- **Description:** The attacker has access to some plaintext-ciphertext pairs and uses them to deduce the encryption key.
- **Example:** Linear cryptanalysis against block ciphers.

#### **7. Chosen-ciphertext Attack**
- **Description:** The attacker chooses ciphertexts to decrypt and uses the results to gain insights into the key.
- **Variants:**
  - **Lunchtime Attack:** Limited access to the decryption system.
  - **Adaptive Attack:** Iterative queries to refine the attack.

#### **8. Rubber Hose Attack**
- **Description:** Physical coercion or torture to extract encryption keys or passwords.
- **Effectiveness:** Dependent on the victim's resistance to pressure.

#### **9. Chosen-key Attack**
- **Description:** The attacker gains control of the encryption system by breaking multiple ciphertexts or exploiting system dependencies.

#### **10. Timing Attack**
- **Description:** Exploits variations in encryption or decryption time to deduce information about the key.

#### **11. Man-in-the-Middle Attack (MITM)**
- **Description:** The attacker intercepts and manipulates communications between two parties to gain access to cryptographic keys or messages.
- **Common Target:** Public key systems during key exchange.

---

### **Code Breaking Techniques**

#### **1. Brute Force Attack**
- **Description:** Attempts all possible key combinations until the correct one is found.
- **Key Factors:**
  - Key length.
  - Processing speed.
  - Lockout mechanisms after failed attempts.
- **Example:** DES 56-bit keys are now considered insecure due to brute force feasibility.

#### **2. Frequency Analysis**
- **Description:** Exploits the frequency of letters or symbols in ciphertext, particularly effective against substitution ciphers.
- **Common Use:** Breaking simple encryption schemes.

#### **3. Trickery and Deceit**
- **Description:** Social engineering techniques to extract cryptographic keys or known plaintext content for analysis.

#### **4. One-Time Pad**
- **Description:** Uses a non-repeating random key equal to the plaintext length, considered unbreakable when used correctly.
- **Drawback:** Impractical for large messages due to key management.

#### **5. Birthday Attack**
- **Description:** Exploits the probability of hash collisions using the **birthday paradox**.
- **Target:** Cryptographic hashes like MD5, SHA-1.

#### **6. Meet-in-the-Middle Attack**
- **Description:** Targets multi-key encryption systems (e.g., Double DES) by analyzing encryption from one end and decryption from the other.
- **Efficiency:** Reduces the required brute force permutations significantly.

---

### **Brute-Forcing VeraCrypt Encryption**

#### **Steps Using Hashcat**
1. **Extract Hash:**
   ```bash
   dd.exe if=<path_to_container> of=<path_to_hashfile.tc> bs=512 count=1
   ```

2. **Brute-force Command:**
   ```bash
   hashcat.exe -a 3 -w 1 -m 13721 <path_to_hashfile.tc> ?d?d?d?d
   ```
   - **Options:**
     - `-a 3`: Brute-force attack mode.
     - `-w 1`: Workload profile.
     - `-m 13721`: Decryption mode for VeraCrypt.
     - `?d`: Indicates numeric digits.

3. **Wordlist-based Attack:**
   ```bash
   hashcat.exe -w 1 -m 13721 hash.tc wordlist.txt
   ```

---

### **Key Takeaways**
- **Preventive Measures:** Employ strong, long keys and secure key management systems.
- **Secure Protocols:** Use modern algorithms (e.g., AES-256, SHA-3) to counteract brute force and cryptanalysis attacks.
- **Mitigation of MITM:** Implement certificate-based authentication and encrypted communication channels.
- ### **Side-Channel Attacks**

#### **Definition**
A **side-channel attack** exploits physical characteristics or unintended information leaks from a cryptographic system to extract sensitive data such as encryption keys. These attacks target how the system implements cryptographic algorithms rather than the algorithms themselves.

#### **Types of Side-Channel Attacks**
1. **Power Consumption:**
   - **Simple Power Analysis (SPA):** Observes power usage patterns to infer operations or data values.
   - **Differential Power Analysis (DPA):** Uses statistical techniques to analyze variations in power consumption and extract cryptographic keys.

2. **Electromagnetic Field:**
   - Measures electromagnetic emissions to deduce the internal computations and data being processed.

3. **Light Emission:**
   - Observes light emissions (e.g., from LEDs or CRTs) to reconstruct processed data or displayed signals.

4. **Timing and Delay:**
   - Exploits variations in the time taken by cryptographic operations to infer secret information.

5. **Sound (Acoustic Attacks):**
   - Uses sound emissions from hardware components like CPUs or keyboards to gather sensitive data.

#### **Mitigation Techniques**
- Use **constant-time algorithms** to eliminate data-dependent timing variations.
- Apply **masking and blinding** techniques to randomize algorithm inputs and outputs.
- Use **tamper-resistant enclosures** or shielding to reduce electromagnetic radiation.
- Introduce **noise** into physical channels to lower the signal-to-noise ratio for attackers.
- Design hardware with **secure elements** such as physically unclonable functions (PUFs) or secure enclaves.
- Employ **security analysis tools** during the design phase to detect vulnerabilities.

---

### **Hash Collision Attack**

#### **Definition**
A **hash collision attack** occurs when an attacker finds two distinct inputs (`a1` and `a2`) that produce the same hash value (`hash(a1) = hash(a2)`). This can be used to exploit systems relying on hash functions for integrity, such as digital signatures.

#### **Popular Vulnerable Hashes**
- **SHA-1:** Widely used but increasingly vulnerable due to successful collision attacks.
- **MD5:** Known for its susceptibility to hash collision attacks.

#### **Example**
An attacker forges a digital signature by generating a malicious document (`a2`) with the same hash as a legitimate document (`a1`).

---

### **DUHK Attack**

#### **Definition**
The **Don't Use Hard-Coded Keys (DUHK)** attack exploits systems that use the ANSI X9.31 RNG with a hardcoded seed key. Attackers can derive encryption keys by observing encrypted communications and deducing the random number generator's state.

#### **Mitigation**
- Avoid hardcoded keys.
- Use modern and secure random number generators, such as those compliant with NIST standards.

---

### **DROWN Attack**

#### **Definition**
The **Decrypting RSA with Obsolete and Weakened eNcryption (DROWN)** attack exploits servers supporting outdated SSLv2 protocols to decrypt modern TLS communications.

#### **Vulnerability Scenarios**
- Servers misconfigured to allow SSLv2 connections.
- Shared private keys between SSLv2 and modern TLS servers.

#### **Impact**
- Decryption of sensitive information such as passwords and credit card details.
- Masquerading as secure websites.

#### **Mitigation**
- Disable SSLv2 on all servers.
- Use unique private keys for modern TLS servers.

---

### **Rainbow Table Attack**

#### **Definition**
A **rainbow table attack** uses precomputed hash values for a list of possible plaintext inputs (e.g., passwords) to reverse cryptographic hash functions and retrieve plaintext from a given hash.

#### **Process**
1. The attacker creates a **rainbow table** mapping plaintexts to hashes.
2. Captured hashes are compared against the table to find matches.

#### **Mitigation**
- Use **salting**: Add random data to plaintext before hashing to prevent precomputed table attacks.
- Employ strong and modern hash algorithms like **SHA-3**.

---

### **Related-Key Attack**

#### **Definition**
A **related-key attack** exploits mathematical relationships between cryptographic keys to derive unknown keys.

#### **Example**
- Wireless networks using WEP with RC4 encryption are vulnerable due to repeated keys.

#### **Mitigation**
- Use encryption algorithms resistant to related-key attacks (e.g., AES).
- Avoid reusing keys or deriving new keys from predictable sources.

---

### **Padding Oracle Attack**

#### **Definition**
A **padding oracle attack** exploits the error messages or feedback from a server when processing incorrectly padded ciphertext. This allows an attacker to decrypt ciphertext or forge messages.

#### **Example**
- Systems using **CBC mode** without properly masking error messages are vulnerable.

#### **Mitigation**
- Use constant-time error handling to avoid revealing padding issues.
- Implement modern encryption schemes like **AEAD (Authenticated Encryption with Associated Data)**.

---

### **Key Takeaways**
1. Side-channel attacks exploit physical and environmental factors. Employ countermeasures like shielding, noise addition, and constant-time operations.
2. Hash collision attacks underline the importance of using collision-resistant hash functions like **SHA-256** or **SHA-3**.
3. Modern cryptographic standards and configurations (e.g., TLS 1.3, AES) effectively mitigate vulnerabilities such as DUHK, DROWN, and related-key attacks.
4. Prevent rainbow table attacks by incorporating **salting** and using robust hashing algorithms.
5. ### **Blockchain Attacks**

Blockchain attacks exploit vulnerabilities in blockchain networks, threatening their integrity, security, and reliability. Below is a summary of notable blockchain attacks and their mechanisms:

---

#### **1. 51% Attack**
- **Definition:** A group or entity gains control over 51% of a network's hash rate or staking power, enabling them to:
  - Reverse transactions (double-spending).
  - Prevent new transactions from being confirmed.
  - Halt the network entirely.

- **Steps:**
  1. Gain control over 51% of the computational power.
  2. Isolate and create a private chain.
  3. Extend the private chain longer than the public chain.
  4. Release the private chain to override the public chain.

- **Impact:** Loss of trust, financial theft, and disruption.

---

#### **2. Finney Attack**
- **Definition:** Exploits the delay between transaction broadcast and confirmation to double-spend cryptocurrency.
- **Steps:**
  1. Pre-mine a block containing a transaction to the attacker's address.
  2. Initiate a transaction with the victim.
  3. Broadcast the pre-mined block to invalidate the victim's transaction.
- **Impact:** Losses for vendors or individuals accepting unconfirmed transactions.

---

#### **3. Eclipse Attack**
- **Definition:** Isolates a target node by surrounding it with malicious nodes to control its view of the network.
- **Steps:**
  1. Fill the target's peer tables with attacker-controlled nodes.
  2. Force the node to restart, disconnecting it from legitimate peers.
  3. Manipulate the target's view of the blockchain.
- **Impact:** Enables transaction manipulation, network disruption, and double-spending.

---

#### **4. Race Attack**
- **Definition:** Exploits the delay in transaction confirmation to double-spend cryptocurrency.
- **Steps:**
  1. Create two conflicting transactions using the same input.
  2. Broadcast one transaction to the victim and another to the network.
  3. Ensure the network confirms the attacker’s transaction first.
- **Impact:** Losses for victims accepting zero-confirmation transactions.

---

#### **5. DeFi Sandwich Attack**
- **Definition:** Manipulates token prices on decentralized exchanges (DEXs) to profit from price changes.
- **Steps:**
  1. Front-run a large transaction by placing a buy order.
  2. Let the victim’s transaction inflate the token price.
  3. Execute a sell order to profit from the price difference.
- **Impact:** Financial losses for traders due to manipulated market prices.

---

### **Quantum Computing Risks to Blockchain**

#### **Key Risks:**
1. **Breaking Public-Key Cryptography:** Quantum algorithms like Shor’s can derive private keys from public keys, compromising blockchain security.
2. **Hash Collisions:** Quantum computing can undermine hash functions, enabling attackers to forge blockchain data.
3. **Harvest-Now, Decrypt-Later:** Adversaries archive encrypted blockchain data for decryption once quantum computers become powerful enough.

---

### **Mitigation Techniques**

#### **Blockchain-Specific Mitigations:**
1. **Use Quantum-Resistant Algorithms:**
   - Integrate quantum-safe cryptographic standards such as lattice-based, code-based, or hash-based cryptography.
2. **Enhance Network Decentralization:**
   - Avoid centralized control of nodes and mining pools to mitigate 51% attacks.
3. **Wait for Multiple Confirmations:**
   - Avoid accepting zero-confirmation transactions to prevent Finney and race attacks.
4. **Implement Peer Diversity:**
   - Ensure nodes connect to a wide variety of peers to resist Eclipse attacks.

#### **Quantum-Related Mitigations:**
1. **Transition to Quantum-Resistant Blockchains:**
   - Gradually replace vulnerable cryptographic methods.
2. **Shorten Public Key Exposure:**
   - Minimize the time public keys are exposed before transactions are confirmed.

---

### **Cryptanalysis Tools**
1. **CrypTool:** An educational platform for cryptographic analysis.
2. **RsaCtfTool:** Specializes in RSA vulnerabilities.
3. **Crypto++:** Comprehensive cryptographic library for analysis.

These tools, along with quantum-safe techniques, help strengthen blockchain and cryptographic security against evolving threats. 
### Cryptography Attack Countermeasures Summary

#### **General Cryptographic Defense Strategies:**
1. **Key Management:**
   - Provide access to cryptographic keys only to authorized applications or users.
   - Use hardware security modules (HSMs) for secure key storage.
   - Encrypt stored keys with strong passphrases or passwords.
   - Avoid embedding keys in source code or binaries.

2. **Algorithm Strength:**
   - Symmetric Key Algorithms: Use at least 256-bit keys.
   - Asymmetric Key Algorithms: Use at least 2048-bit keys.
   - Hash Functions: Employ hash lengths of 256 bits or more (e.g., SHA-256 or SHA-3).

3. **Security Practices:**
   - Implement message authentication for symmetric protocols.
   - Regularly rotate encryption keys.
   - Use standardized cryptographic tools instead of custom solutions.
   - Adopt redundant cryptosystems for multi-layer encryption.

4. **Secure Application Design:**
   - Avoid predictable encryption outputs by using probabilistic encryption.
   - Combine confidentiality and integrity methods (e.g., AES-GCM or Encrypt-then-MAC).

---

#### **Blockchain-Specific Countermeasures:**
1. **Identity Verification:**
   - Use decentralized identifiers (DIDs) and zero-knowledge proofs.
   - Employ multi-signature wallets for transaction authorization.

2. **Transaction Security:**
   - Implement real-time monitoring to detect anomalies.
   - Wait for multiple confirmations before accepting transactions.
   - Use batch processing and fair sequencing to prevent transaction reordering.

3. **Node Protection:**
   - Randomize peer selection and enforce connection timeouts.
   - Monitor mining pools to avoid 51% attacks.
   - Use trusted bootstrapping nodes for new node connections.

4. **Consensus Mechanisms:**
   - Combine proof-of-work (PoW) with proof-of-stake (PoS) to mitigate vulnerabilities.
   - Regularly audit and verify smart contracts.

---

#### **Quantum Computing Defense Strategies:**
1. **Adopt Quantum-Resistant Cryptography:**
   - Use lattice-based, hash-based, or code-based cryptographic algorithms.
   - Transition to post-quantum cryptographic standards as they emerge.

2. **Secure Data Distribution:**
   - Use quantum key distribution (QKD) for secure key exchange.
   - Fragment and distribute sensitive data to avoid full compromise.

3. **System Protection:**
   - Employ modular cryptographic systems to facilitate quick updates.
   - Develop quantum-resistant authentication protocols and digital signatures.

4. **Hybrid and Backup Mechanisms:**
   - Combine classical cryptographic methods with quantum-resistant algorithms.
   - Regularly update and rotate cryptographic keys.

5. **Infrastructure Readiness:**
   - Equip hardware with quantum-resistant TPMs.
   - Integrate quantum-safe measures into CI/CD pipelines and SDLC processes.

---

#### **Key Stretching Techniques:**
- **Purpose:** Strengthen weak keys to resist brute-force attacks.
- **Methods:**
  - **PBKDF2:** Uses hash functions with salt to produce derived keys.
  - **Bcrypt:** Based on Blowfish, hashes passwords with salt for enhanced security.
  - **Argon2:** Optimized for resistance to GPU-based attacks.

---

### **Best Practices Summary:**
- **Adopt Strong Standards:** Ensure compliance with industry security standards like NIST.
- **Encrypt Communication:** Use protocols like TLS to secure communication and validate identities.
- **Monitor and Update Regularly:** Regularly review systems for vulnerabilities and update algorithms to withstand new threats.
- **Educate Users:** Promote secure practices, such as using complex passwords and multi-factor authentication.

These strategies collectively enhance cryptographic defenses, safeguarding data from both conventional and emerging threats.

# SUMMARIZED PICTURES:

![WhatsApp Image 2024-12-22 at 13 00 25_4bad8556](https://github.com/user-attachments/assets/ae8f1baa-f94b-43a6-b200-217d70bc1e61)

![WhatsApp Image 2024-12-22 at 13 00 25_da205389](https://github.com/user-attachments/assets/2fe28440-a11d-4ea3-aa94-c89da8e81650)

![WhatsApp Image 2024-12-22 at 13 00 25_3826f416](https://github.com/user-attachments/assets/28b4c9f4-b91a-418d-a245-40ce6560a25d)

![WhatsApp Image 2024-12-22 at 13 00 25_f5a35756](https://github.com/user-attachments/assets/f086946f-bd32-491d-8c4d-7a8af3d42373)

![WhatsApp Image 2024-12-22 at 13 00 26_6ccccbd0](https://github.com/user-attachments/assets/32721758-9a01-49ec-885e-abe7ef0ea7ec)

![WhatsApp Image 2024-12-22 at 13 00 26_f4b35a14](https://github.com/user-attachments/assets/ea599d1b-a16a-422d-a0ae-1228997440c5)

![WhatsApp Image 2024-12-22 at 13 00 26_09ff6cd8](https://github.com/user-attachments/assets/18b22369-d200-4468-818c-0786121b6de4)
![WhatsApp Image 2024-12-22 at 13 00 27_28eb3a5e](https://github.com/user-attachments/assets/7bb8254f-06c0-41ec-86f8-977664efe96f)
![WhatsApp Image 2024-12-22 at 13 00 27_79311eb5](https://github.com/user-attachments/assets/32c8d12a-361a-4a09-af7a-8f56b7df6da7)
![WhatsApp Image 2024-12-22 at 13 00 27_a2d5eb42](https://github.com/user-attachments/assets/775f9dda-9550-4410-a1ea-aae94e387d14)
![WhatsApp Image 2024-12-22 at 13 00 28_78427610](https://github.com/user-attachments/assets/f3dff909-8b36-467b-8183-2c244de102f7)

![WhatsApp Image 2024-12-22 at 13 00 28_364f1091](https://github.com/user-attachments/assets/d9181bc1-b674-4332-b373-088c63c1cd12)


![WhatsApp Image 2024-12-22 at 13 00 28_7dbafce0](https://github.com/user-attachments/assets/9108b1de-60f4-4209-8e5c-a123d94e53b9)



![WhatsApp Image 2024-12-22 at 13 00 28_a46dfb0e](https://github.com/user-attachments/assets/f6199992-8b90-4883-9204-dee3ddead127)


![WhatsApp Image 2024-12-22 at 13 00 29_3c76ec15](https://github.com/user-attachments/assets/da87a7df-adb2-4ee9-9d45-c7f8e718db0f)


![WhatsApp Image 2024-12-22 at 13 00 29_7ea1c10d](https://github.com/user-attachments/assets/94cd0750-d219-454c-a2ff-e5cca3c1e7ce)
![WhatsApp Image 2024-12-22 at 13 00 29_9b0fd9ab](https://github.com/user-attachments/assets/3bb92cfc-64c9-4710-8ede-6ba29dab2a6b)
![WhatsApp Image 2024-12-22 at 13 00 30_5f0b3c9c](https://github.com/user-attachments/assets/94dccaff-1217-49da-b754-a3f6266d8544)

![WhatsApp Image 2024-12-22 at 13 00 30_7171ecb0](https://github.com/user-attachments/assets/5dedc2d7-c686-4b6a-9abe-92aa56385c31)

![WhatsApp Image 2024-12-22 at 13 00 30_cc6b57ac](https://github.com/user-attachments/assets/c49c3a91-e7a4-411d-a647-1552cb3c0731)
![WhatsApp Image 2024-12-22 at 13 00 31_0e6406c4](https://github.com/user-attachments/assets/51527366-5e36-4114-b29b-e49b343f5a44)


![WhatsApp Image 2024-12-22 at 13 00 31_b63f7b7f](https://github.com/user-attachments/assets/f32383de-3da2-40c6-a642-537cbd7a00eb)
![WhatsApp Image 2024-12-22 at 13 00 31_cde51189](https://github.com/user-attachments/assets/31a992ba-32b8-4c19-b082-64c50a5b4990)


![WhatsApp Image 2024-12-22 at 13 00 32_33897188](https://github.com/user-attachments/assets/2fb8b6e5-941d-492b-8ba2-3dff5578137c)

![WhatsApp Image 2024-12-22 at 13 00 32_edd8c39b](https://github.com/user-attachments/assets/a6920aad-ec3f-4a20-829a-7933ea7bdea7)
![WhatsApp Image 2024-12-22 at 13 00 33_afdefed7](https://github.com/user-attachments/assets/ed5e033b-7b63-44f0-9fa8-7dcdc0a4af94)

![WhatsApp Image 2024-12-22 at 13 00 33_749d6ab6](https://github.com/user-attachments/assets/90fec436-fc91-4b02-82c7-d0cc33796897)
![WhatsApp Image 2024-12-22 at 13 00 33_32ad36bd](https://github.com/user-attachments/assets/633bd15a-e3f4-4baf-8261-66ec224017bb)
![WhatsApp Image 2024-12-22 at 13 00 34_0fa53d4c](https://github.com/user-attachments/assets/a4311929-d58d-42f4-8f8a-d6ad32f8f898)
![WhatsApp Image 2024-12-22 at 13 00 34_262de569](https://github.com/user-attachments/assets/6f2539c9-f18b-4842-b9f4-8f069c4bfd77)
![WhatsApp Image 2024-12-22 at 13 00 34_e2333829](https://github.com/user-attachments/assets/c9bbea32-610f-41f2-91d9-0f81a0b3aa47)
![WhatsApp Image 2024-12-22 at 13 00 35_e77ea5b6](https://github.com/user-attachments/assets/39c79c62-1a3e-4c1a-a280-6b25c93096f2)

















