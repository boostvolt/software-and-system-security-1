# Lab 07: Java Cryptography Architecture (JCA) - Solutions

---

# SLCrypt: Hybrid Encryption Implementation

## Challenge Overview

**Goal**: Implement a file encryption program using hybrid encryption (symmetric + asymmetric cryptography) with optional MAC/signature authentication.

**Components to Implement**:

- Secret key generation for various ciphers
- RSA encryption of secret keys
- File header generation with IV/nonce
- Document encryption with multiple cipher modes
- HMAC computation for authentication
- RSA signature computation for non-repudiation

---

## Supported Algorithms

### Encryption Algorithms

| Algorithm             | Key Length(s) | IV Length | Notes                        |
| --------------------- | ------------- | --------- | ---------------------------- |
| AES/CBC/PKCS5Padding  | 128, 192, 256 | 16 bytes  | Block cipher with padding    |
| AES/GCM/NoPadding     | 128, 192, 256 | 16 bytes  | Authenticated encryption     |
| AES/CTR/NoPadding     | 128, 192, 256 | 16 bytes  | Counter mode (stream cipher) |
| SEED/CBC/PKCS5Padding | 128           | 16 bytes  | Requires Bouncy Castle       |
| SEED/GCM/NoPadding    | 128           | 16 bytes  | Requires Bouncy Castle       |
| SEED/CTR/NoPadding    | 128           | 16 bytes  | Requires Bouncy Castle       |
| RC4                   | 128           | 0 bytes   | Stream cipher (no IV)        |
| CHACHA20              | 256           | 12 bytes  | Modern stream cipher         |

### MAC Algorithms

| Algorithm    | Hash Function |
| ------------ | ------------- |
| HmacSHA1     | SHA-1         |
| HmacSHA256   | SHA-2 (256)   |
| HmacSHA512   | SHA-2 (512)   |
| HmacSHA3-256 | SHA-3 (256)   |
| HmacSHA3-512 | SHA-3 (512)   |

### Signature Algorithms

| Algorithm       | Hash Function |
| --------------- | ------------- |
| SHA1withRSA     | SHA-1         |
| SHA256withRSA   | SHA-2 (256)   |
| SHA512withRSA   | SHA-2 (512)   |
| SHA3-256withRSA | SHA-3 (256)   |
| SHA3-512withRSA | SHA-3 (512)   |

---

## Implementation: HybridEncryptionImpl.java

### Required Imports

```java
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.ChaCha20ParameterSpec;
import ch.zhaw.securitylab.slcrypt.FileHeader;
import ch.zhaw.securitylab.slcrypt.Helpers;
```

---

### Method 1: generateSecretKey

**Purpose**: Create a cryptographically secure random key for symmetric encryption.

**Initial Code (Skeleton)**:

```java
protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {
    // To do...
    return null;
}
```

**Solution Code**:

```java
protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {
    try {
        String cipherName = Helpers.getCipherName(cipherAlgorithm);

        // SEED cipher requires special handling (Bouncy Castle)
        if (cipherName.equals("SEED")) {
            byte[] key = new byte[16];  // SEED always uses 128-bit key
            SecureRandom random = new SecureRandom();
            random.nextBytes(key);
            return key;
        }

        // Standard key generation for other ciphers
        KeyGenerator kg = KeyGenerator.getInstance(cipherName);
        kg.init(keyLength);
        SecretKey key = kg.generateKey();

        return key.getEncoded();

    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
        return null;
    }
}
```

**Key Points**:

- `Helpers.getCipherName()` extracts cipher name from full algorithm string (e.g., "AES" from "AES/CBC/PKCS5Padding")
- SEED cipher needs special handling because Java's standard `KeyGenerator` doesn't support it
- `SecureRandom` provides cryptographically strong random numbers
- `getEncoded()` returns the raw key bytes

---

### Method 2: encryptSecretKey

**Purpose**: Encrypt the symmetric key using the recipient's RSA public key (from their certificate).

**Initial Code (Skeleton)**:

```java
protected byte[] encryptSecretKey(byte[] secretKey, InputStream certificateEncrypt) {
    // To do...
    return null;
}
```

**Solution Code**:

```java
protected byte[] encryptSecretKey(byte[] secretKey, InputStream certificateEncrypt) {
    try {
        // Parse X.509 certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(certificateEncrypt);

        // Use RSA with OAEP padding (secure padding scheme)
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());

        return cipher.doFinal(secretKey);

    } catch (CertificateException | NoSuchAlgorithmException | NoSuchPaddingException
            | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
        e.printStackTrace();
        return null;
    }
}
```

**Key Points**:

- `RSA/ECB/OAEPPadding` uses PKCS#1 v2 (OAEP) padding - more secure than PKCS#1 v1.5
- Certificate contains the public key for asymmetric encryption
- The encrypted secret key will be stored in the file header

---

### Method 3: generateFileHeader

**Purpose**: Create file header containing metadata needed for decryption.

**Initial Code (Skeleton)**:

```java
protected FileHeader generateFileHeader(String cipherAlgorithm, char authIntType,
        String authIntAlgorithm, InputStream certificateVerify, byte[] encryptedSecretKey) {
    // To do...
    return null;
}
```

**Solution Code**:

```java
protected FileHeader generateFileHeader(String cipherAlgorithm, char authIntType,
        String authIntAlgorithm, InputStream certificateVerify, byte[] encryptedSecretKey) {
    try {
        FileHeader header = new FileHeader();

        // Set cipher algorithm
        header.setCipherAlgorithm(cipherAlgorithm);

        // Generate and set IV if required by the cipher
        if (Helpers.hasIV(cipherAlgorithm)) {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[Helpers.getIVLength(cipherAlgorithm)];
            random.nextBytes(iv);
            header.setIV(iv);
        } else {
            header.setIV(new byte[0]);  // RC4 doesn't use IV
        }

        // Set authentication/integrity protection type and algorithm
        header.setAuthIntType(authIntType);
        header.setAuthIntAlgorithm(authIntAlgorithm);

        // Include certificate for signature verification
        if (authIntType == Helpers.SIGNATURE && certificateVerify != null) {
            ByteArrayOutputStream certBytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = certificateVerify.read(buffer)) != -1) {
                certBytes.write(buffer, 0, bytesRead);
            }
            header.setCertificate(certBytes.toByteArray());
        } else {
            header.setCertificate(new byte[0]);
        }

        // Set the RSA-encrypted secret key
        header.setEncryptedSecretKey(encryptedSecretKey);

        return header;

    } catch (IOException e) {
        e.printStackTrace();
        return null;
    }
}
```

**Key Points**:

- IV must be generated randomly using `SecureRandom`
- IV length depends on cipher: 16 bytes for AES/SEED, 12 bytes for CHACHA20
- Certificate is only included when using signatures (for verification)
- Empty arrays (length 0) used for optional fields when not applicable

---

### Method 4: encryptDocument

**Purpose**: Encrypt the plaintext document using the symmetric key with the specified cipher.

**Initial Code (Skeleton)**:

```java
protected byte[] encryptDocument(InputStream document, FileHeader fileHeader, byte[] secretKey) {
    // To do...
    return null;
}
```

**Solution Code**:

```java
protected byte[] encryptDocument(InputStream document, FileHeader fileHeader, byte[] secretKey) {
    try {
        String cipherName = fileHeader.getCipherAlgorithm();
        Cipher cipher = Cipher.getInstance(cipherName);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey, Helpers.getCipherName(cipherName));

        // Initialize cipher based on mode
        if (Helpers.isGCM(cipherName)) {
            // GCM mode: requires GCMParameterSpec with auth tag length
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(
                Helpers.AUTH_TAG_LENGTH, fileHeader.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            // Add file header as additionally authenticated data (AAD)
            cipher.updateAAD(fileHeader.encode());

        } else if (cipherName.contains("CHACHA20")) {
            // CHACHA20: requires nonce and counter
            ChaCha20ParameterSpec chacha20Spec = new ChaCha20ParameterSpec(
                fileHeader.getIV(), 1);  // Counter starts at 1
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, chacha20Spec);

        } else if (Helpers.hasIV(cipherName)) {
            // CBC/CTR modes: require IvParameterSpec
            IvParameterSpec ivSpec = new IvParameterSpec(fileHeader.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        } else {
            // RC4: no IV needed
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }

        // Encrypt document stream
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int bytesRead;

        while ((bytesRead = document.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                baos.write(output);
            }
        }

        // Finalize encryption (handles padding for block ciphers)
        byte[] finalBlock = cipher.doFinal();
        if (finalBlock != null) {
            baos.write(finalBlock);
        }

        return baos.toByteArray();

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException | IOException | IllegalBlockSizeException
            | BadPaddingException e) {
        e.printStackTrace();
        return null;
    }
}
```

**Key Points**:

- Different cipher modes require different parameter specifications:
  - **GCM**: `GCMParameterSpec` with auth tag length (128 bits) and IV
  - **CHACHA20**: `ChaCha20ParameterSpec` with nonce and counter (1)
  - **CBC/CTR**: `IvParameterSpec` with IV
  - **RC4**: No parameters needed
- GCM mode includes file header as Additional Authenticated Data (AAD)
- `update()` processes input incrementally, `doFinal()` handles final block/padding

---

### Method 5: computeMAC

**Purpose**: Compute HMAC for authentication and integrity protection.

**Initial Code (Skeleton)**:

```java
protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm, byte[] password) {
    // To do...
    return null;
}
```

**Solution Code**:

```java
protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm, byte[] password) {
    try {
        Mac mac = Mac.getInstance(macAlgorithm);
        SecretKeySpec keySpec = new SecretKeySpec(password, macAlgorithm);
        mac.init(keySpec);

        return mac.doFinal(dataToProtect);

    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
        e.printStackTrace();
        return null;
    }
}
```

**Key Points**:

- Password is used as the HMAC key
- `doFinal()` computes MAC over entire input in one call
- MAC computed over FileHeader + EncryptedDocument (Encrypt-then-MAC pattern)

---

### Method 6: computeSignature

**Purpose**: Compute RSA digital signature for non-repudiation.

**Initial Code (Skeleton)**:

```java
protected byte[] computeSignature(byte[] dataToProtect, String signatureAlgorithm,
        InputStream privateKeySign) {
    // To do...
    return null;
}
```

**Solution Code**:

```java
protected byte[] computeSignature(byte[] dataToProtect, String signatureAlgorithm,
        InputStream privateKeySign) {
    try {
        // Read private key from input stream
        PKCS8EncodedKeySpec keySpec;
        {
            ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = privateKeySign.read(buffer)) != -1) {
                keyBytes.write(buffer, 0, bytesRead);
            }
            keySpec = new PKCS8EncodedKeySpec(keyBytes.toByteArray());
        }

        // Generate private key object from PKCS#8 encoded data
        KeyFactory kf = KeyFactory.getInstance("RSA");

        // Initialize signature with private key
        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initSign(kf.generatePrivate(keySpec));

        // Compute signature
        sig.update(dataToProtect);
        return sig.sign();

    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException
            | InvalidKeyException | SignatureException e) {
        e.printStackTrace();
        return null;
    }
}
```

**Key Points**:

- Private key is PKCS#8 encoded (DER format)
- `KeyFactory` converts encoded bytes to `PrivateKey` object
- Signature algorithm includes hash function (e.g., "SHA256withRSA")
- Signature computed over FileHeader + EncryptedDocument

---

## File Format

The encrypted file has the following structure:

```
[ FileHeader | Encrypted Document | MAC/Signature (optional) ]
```

### FileHeader Structure

| Field                     | Size     | Description                                   |
| ------------------------- | -------- | --------------------------------------------- |
| SLCRYPT                   | 7 bytes  | Magic identifier                              |
| Version                   | 1 byte   | Format version (1)                            |
| Cipher Algorithm Length   | 1 byte   | Length of cipher name                         |
| Cipher Algorithm          | variable | e.g., "AES/CBC/PKCS5Padding"                  |
| IV Length                 | 1 byte   | Length of IV (0 if no IV)                     |
| IV                        | variable | Initialization vector                         |
| Auth/Int Type             | 1 byte   | 'M' (MAC), 'S' (Signature), or 'N' (None)     |
| Auth/Int Algorithm Length | 1 byte   | Length of auth algorithm name                 |
| Auth/Int Algorithm        | variable | e.g., "HmacSHA256"                            |
| Certificate Length        | 2 bytes  | Length of verification certificate            |
| Certificate               | variable | X.509 certificate for signature verification  |
| Encrypted Key Length      | 2 bytes  | Length of RSA-encrypted secret key            |
| Encrypted Secret Key      | variable | Secret key encrypted with recipient's RSA key |

---

## Setup: Bouncy Castle Provider

For SEED cipher support:

1. Download Bouncy Castle:

   ```
   https://www.bouncycastle.org/download/bouncy-castle-java
   ```

2. Edit `/usr/lib/jvm/java-21-openjdk-amd64/conf/security/java.security`:

   ```
   security.provider.13=org.bouncycastle.jce.provider.BouncyCastleProvider
   ```

3. Include in classpath when running:
   ```bash
   java -cp bcprov-jdk18on-1.81.jar:. ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt ...
   ```

---

## Usage Examples

### Example 1: AES-GCM with no authentication

```bash
java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt \
    data/testdoc.txt data/testdoc.enc data/encryptCert.crt \
    AES/GCM/NoPadding 128 N
```

### Example 2: AES-CBC with HMAC-SHA256

```bash
java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt \
    data/testdoc.txt data/testdoc.enc data/encryptCert.crt \
    AES/CBC/PKCS5Padding 192 M HmacSHA256 supersecret
```

### Example 3: CHACHA20 with RSA signature

```bash
java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt \
    data/testdoc.txt data/testdoc.enc data/encryptCert.crt \
    CHACHA20 256 S SHA512withRSA data/signKey.key data/signCert.crt
```

### Decryption with MAC

```bash
java ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt \
    data/testdoc.enc data/testdoc.dec data/encryptKey.key supersecret
```

### Decryption with signature (no password needed)

```bash
java ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt \
    data/testdoc.enc data/testdoc.dec data/encryptKey.key
```

---

## Security Considerations

### Why Encrypt-then-MAC?

The implementation uses **Encrypt-then-MAC** pattern:

1. First encrypt the document
2. Then compute MAC/signature over ciphertext + header

This is more secure than MAC-then-Encrypt because:

- Prevents padding oracle attacks
- MAC verification can reject invalid messages before decryption
- No information leakage through MAC verification timing

### Why OAEP Padding for RSA?

`RSA/ECB/OAEPPadding` uses PKCS#1 v2 (OAEP) which is:

- Provably secure under chosen ciphertext attacks
- Better than older PKCS#1 v1.5 padding
- Recommended for all new implementations

### Why GCM Mode?

GCM provides both:

- **Confidentiality** (encryption)
- **Authenticity/Integrity** (via auth tag)

However, SLCrypt still supports additional MAC/signature because:

- The key exchange itself isn't authenticated
- Without additional auth, attacker could substitute their own message
- Adding MAC/signature provides end-to-end authentication
