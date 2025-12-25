package ch.zhaw.securitylab.marketplace.service;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@Service
public class AESCipherService {

    private final static String CIPHER_ALGORITHM = "AES";
    private final static String CIPHER_ALGORITHM_FULL = "AES/GCM/NoPadding";
    private final static int BLOCKSIZE = 16;
    private final static int AUTH_TAG_LENGTH = 128;
    private static SecretKeySpec keySpec;

    // Static initializer to read key from file system and set keyspec
    {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(Thread.currentThread().
                    getContextClassLoader().getResourceAsStream("keystore/db-key")));
            String hexKey = reader.readLine();
            byte[] byteKey = toByteArray(hexKey);
            keySpec = new SecretKeySpec(byteKey, CIPHER_ALGORITHM);
        } catch (IOException e) {
            // Do nothing
        }
    }

    /**
     * Encrypts (and integrity-protects) the plaintext with AES in GCM mode,
     * selecting a random IV. The length of the Auth Tag is 128 bits.
     *
     * @param plaintext The plaintext to encrypt
     * @return The IV and ciphertext (concatenated)
     */
    public byte[] encrypt(byte[] plaintext) {
        try {
            // Generate a random IV
            byte[] iv = new byte[BLOCKSIZE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Initialize cipher for encryption
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_FULL);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            // Encrypt the plaintext
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Concatenate IV and ciphertext
            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

            return result;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypts iv_ciphertext with AES in GCM mode.
     *
     * @param iv_ciphertext The IV and ciphertext (concatenated)
     * @return The plaintext
     */
    public byte[] decrypt(byte[] iv_ciphertext) {
        try {
            // Extract IV from the beginning
            byte[] iv = new byte[BLOCKSIZE];
            System.arraycopy(iv_ciphertext, 0, iv, 0, BLOCKSIZE);

            // Extract ciphertext (rest of the data)
            byte[] ciphertext = new byte[iv_ciphertext.length - BLOCKSIZE];
            System.arraycopy(iv_ciphertext, BLOCKSIZE, ciphertext, 0, ciphertext.length);

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_FULL);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            // Decrypt and return
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    private static byte[] toByteArray(String hexString) {
        int len = hexString.length();
        byte[] bytes = new byte[len/2];
        for (int i = 0; i < len; i += 2) {
            bytes[i/2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) +
                                  Character.digit(hexString.charAt(i+1), 16));
        }
        return bytes;
    }
}