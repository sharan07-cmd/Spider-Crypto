# CryptoVault Project Write-up
**Name:** == R Sharan Gopalan  
**Roll No:** 106125098  

---

## Stage 1: Caesar Lock
* **Concept Implemented:** This stage implements a classic Caesar Cipher via a Command Line Interface. It operates by   shifting the ASCII values of alphabetical characters and numbers by a fixed, user-defined integer key. It also includes an automated cracking mechanism that brute-forces the ciphertext using frequency analysis, scoring the outputs based on the occurrence of common English letters ("ETAOINSHR") to guess the plaintext without the key.
* **What it protects against:** It provides extremely basic confusion, hiding the plaintext from a casual observer who is quickly glancing at the data, offering a low level of confidentiality.
* **Limitations:** The cipher is trivially breakable for two reasons. First, the key space is incredibly small (only 25 possible alphabetical shifts). 
Second, it operates on a 1-to-1 substitution mapping, meaning it perfectly preserves the underlying structural properties of the language. Because certain letters (like 'E' or 'T') appear with a highly predictable frequency in English, frequency analysis can easily map the most common ciphertext character back to 'E', instantly shattering the encryption.
* **Engineering Notes:** To make the cipher more robust, I engineered the encryption logic to isolate and preserve punctuation while applying separate modular arithmetic wrapping for uppercase letters (modulo 26), lowercase letters (modulo 26), and numerical digits (modulo 10). I also utilized a sorted tuple-based leaderboard array to cleanly rank the top three most likely plaintexts during the cracking process.
---

## Stage 2: Hash Guard
* **Concept Implemented:** This stage introduces a data integrity verification system using the SHA-256 cryptographic hashing algorithm. The script hashes the original plaintext and packages it directly with the ciphertext using a custom string delimiter (hash||ciphertext). Upon decryption, the script recalculates the hash of the newly decrypted text and compares it to the original hash to confirm authenticity.
* **What it protects against:** While the cipher (encryption) provides confidentiality by hiding the data, the Hash Guard provides integrity. It protects against active tampering or random data corruption in transit. You need both because an attacker might not be able to read an encrypted file, but they could still maliciously flip bits inside the file to destroy the receiver's data. The hash ensures the receiver is warned immediately if the file was altered.
* **Limitations:** In this specific implementation, the SHA-256 hash is appended in plain text and is not cryptographically signed (like an HMAC). Because the underlying encryption is just a Caesar cipher, a knowledgeable attacker could intercept the file, crack the cipher, alter the plaintext, generate a brand new SHA-256 hash, and repackage the file without the receiver ever knowing.
* **Engineering Notes:** To efficiently transmit both the hash and the encrypted data as a single package, I used a string concatenation method with a || delimiter. During the decryption and verification phase, the script easily parses this package using Python's split("||") function, separating the cryptographic seal from the payload before processing.

---

## Stage 3: AES Upgrade
* **Concept Implemented:** This stage replaces the vulnerable Caesar cipher with military-grade AES-256 encryption operating in Cipher Block Chaining (CBC) mode, padded with PKCS7. Because AES requires a mathematically perfect 32-byte key, the system uses PBKDF2 (Password-Based Key Derivation Function 2) with a randomly generated 16-byte salt and 500,000 iterations to derive a secure key from a human-readable password. The file is packaged into a single binary string containing the Salt, a random 16-byte Initialization Vector (IV), a SHA-256 integrity hash, and the ciphertext.
* **What it protects against:** It completely eliminates the threat of frequency analysis and small key-space brute-forcing that defeated the Caesar cipher. It also expands protection to *all* file types (binary, video, images), not just plain text, providing robust data confidentiality.
* **Limitations:** While the SHA-256 hash successfully detects random data corruption (integrity), it is not a cryptographically authenticated seal (like an HMAC or AES-GCM). A sophisticated attacker who somehow obtained the password could technically decrypt the file, alter the contents, compute a new plain hash, and repackage the `.enc` file without triggering the tamper alarm.
* **Engineering Notes:** To handle the file packaging securely, I utilized Python's fixed-byte slicing to cleanly unpack the header on decryption. By knowing the exact byte sizes of the cryptographic primitives (16-byte salt, 16-byte IV, and 32-byte SHA-256 hash), the script extracts the necessary decryption parameters and safely isolates the ciphertext payload without requiring any fragile string delimiters.

---

## Stage 4: Hybrid RSA-AES Secure Transport System
* **Concept Implemented:** This stage implements a military-grade Hybrid Encryption architecture, which is the exact fundamental design behind HTTPS and the modern TLS protocol. Because asymmetric encryption (RSA) cannot handle large files, and symmetric encryption (AES) suffers from the key-distribution problem, this system merges the two. It uses AES-256 (CBC Mode) to encrypt the massive data payload quickly, and uses RSA-2048 (with OAEP padding) exclusively to lock up and safely transmit the 32-byte AES temporary key.

* **What it protects against:** * **Man-in-the-Middle (MITM) Interception:** Because the AES key is locked using the Receiver's Public Key, a hacker intercepting the `.enc` file over a compromised network only receives meaningless mathematical static. 
  * **File Tampering:** The system bakes a SHA-256 hash of the original file into the encrypted byte-string. If an attacker flips a single bit during transit, the decryption script's emergency kill-switch aborts the process before writing the corrupted file to the disk.

* **Limitations:** The primary limitation is the strict mathematical size limit imposed by RSA. An RSA-2048 key can only encrypt a maximum of 190 bytes of raw data at a time, as 66 bytes are strictly reserved for OAEP padding (MGF1 mask, SHA-256 hash, and marker bytes). This mathematical "tax" and the heavy computational overhead of prime-number calculus are exactly why we cannot use RSA to encrypt the large files directly.

* **Engineering Notes:** During the architecture design and review, I realized that the 16-byte `salt` generated alongside the AES key was entirely redundant. Since the AES key is generated via `os.urandom(32)` rather than stretched from a human-readable password using a Key Derivation Function, the salt served no purpose. I deprecated the salt and recalculated the fixed-byte offsets for the receiver's array slicing (shifting the hash and ciphertext offsets back by 16 bytes) to optimize the final `.enc` payload size.