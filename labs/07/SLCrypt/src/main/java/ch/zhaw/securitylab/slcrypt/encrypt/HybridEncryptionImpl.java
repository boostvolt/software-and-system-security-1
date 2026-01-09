package ch.zhaw.securitylab.slcrypt.encrypt;

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
import javax.crypto.CipherInputStream;
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
import java.io.ByteArrayInputStream;
import java.util.Arrays;

/**
 * A concrete implementation of the abstract class HybridEncryption.
 */
public class HybridEncryptionImpl extends HybridEncryption {

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength       The key length in bits
     * @return The secret key
     */
    @Override
    protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {

        try {

            String cipherName = Helpers.getCipherName(cipherAlgorithm);

            if (cipherName.equals("SEED")) {
                byte[] key = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(key);
                return key;
            }

            KeyGenerator kg = KeyGenerator.getInstance(cipherName);

            kg.init(keyLength);
            SecretKey key = kg.generateKey();

            return key.getEncoded();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey          The secret key to encrypt
     * @param certificateEncrypt An input stream from which the certificate with
     *                           the public key for encryption can be read
     * @return The encrypted secret key
     */
    @Override
    protected byte[] encryptSecretKey(byte[] secretKey,
            InputStream certificateEncrypt) {

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(certificateEncrypt);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());

            return cipher.doFinal(secretKey);
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Creates a file header object and fills it with the cipher algorithm name,
     * the IV (which must first be created), the authentication and integrity
     * protection type and algorithm name, the certificate, and the encrypted
     * secret key.
     *
     * @param cipherAlgorithm    The cipher algorithm to use
     * @param authIntType        The type to use for authentication and integrity
     *                           protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm   The algorithm to use for authentication and
     *                           integrity protection
     * @param certificateVerify  An input stream from which the certificate for
     *                           signature verification can be read
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    @Override
    protected FileHeader generateFileHeader(String cipherAlgorithm,
            char authIntType, String authIntAlgorithm,
            InputStream certificateVerify, byte[] encryptedSecretKey) {

        try {

            FileHeader header = new FileHeader();

            header.setCipherAlgorithm(cipherAlgorithm);

            if (Helpers.hasIV(cipherAlgorithm)) {
                SecureRandom random = new SecureRandom();
                byte[] iv = new byte[Helpers.getIVLength(cipherAlgorithm)];
                random.nextBytes(iv);
                header.setIV(iv);
            } else {
                header.setIV(new byte[0]);
            }

            header.setAuthIntType(authIntType);
            header.setAuthIntAlgorithm(authIntAlgorithm);

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

            header.setEncryptedSecretKey(encryptedSecretKey);

            return header;

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document   The document to encrypt
     * @param fileHeader The file header that contains information for
     *                   encryption
     * @param secretKey  The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    @Override
    protected byte[] encryptDocument(InputStream document,
            FileHeader fileHeader, byte[] secretKey) {

        try {
            String cipherName = fileHeader.getCipherAlgorithm();
            Cipher cipher = Cipher.getInstance(cipherName);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, Helpers.getCipherName(cipherName));

            if (Helpers.isGCM(cipherName)) {
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Helpers.AUTH_TAG_LENGTH, fileHeader.getIV());
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
                cipher.updateAAD(fileHeader.encode());
            } else if (cipherName.contains("CHACHA20")) {
                ChaCha20ParameterSpec chacha20Spec = new ChaCha20ParameterSpec(fileHeader.getIV(), 1);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, chacha20Spec);
            } else if (Helpers.hasIV(cipherName)) {
                IvParameterSpec ivSpec = new IvParameterSpec(fileHeader.getIV());
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = document.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    baos.write(output);
                }
            }

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

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm  The MAC algorithm to use
     * @param password      The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    @Override
    protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm,
            byte[] password) {
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

    /**
     * Computes the signature over a byte array.
     *
     * @param dataToProtect      The input over which to compute the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param privateKeySign     An input stream from which the private key to sign
     *                           can be read
     * @return The byte array that contains the signature
     */
    @Override
    protected byte[] computeSignature(byte[] dataToProtect,
            String signatureAlgorithm, InputStream privateKeySign) {

        try {

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

            KeyFactory kf = KeyFactory.getInstance("RSA");

            Signature sig = Signature.getInstance(signatureAlgorithm);
            sig.initSign(kf.generatePrivate(keySpec));

            sig.update(dataToProtect);
            return sig.sign();

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException
                | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }
}
