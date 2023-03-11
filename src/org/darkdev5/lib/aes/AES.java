package org.darkdev5.lib.aes;

import org.darkdev5.lib.serialization.Serialization;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * @author darkDev5
 * @version 1.0
 * @since 17
 */
public class AES {
    public static final int AES_KEY_128;
    public static final int AES_KEY_192;
    public static final int AES_KEY_256;

    private SecretKey key;
    private IvParameterSpec iv;

    private String secretKeyFilePath;
    private String ivFilePath;

    static {
        AES_KEY_128 = 128;
        AES_KEY_192 = 192;
        AES_KEY_256 = 256;
    }

    public AES(SecretKey key, IvParameterSpec iv) {
        this.key = key;
        this.iv = iv;
    }

    public AES(String secretKeyFilePath, String ivFilePath) throws IOException {
        this.secretKeyFilePath = secretKeyFilePath;
        this.ivFilePath = ivFilePath;

        loadFromFile();
    }

    /**
     * Loads secret key and initialization vector from file.
     *
     * @throws IOException Throws IOException if unable to load the vector.
     */
    private void loadFromFile() throws IOException {
        Serialization<SecretKey> secretKeySerialization = new Serialization<>(secretKeyFilePath, key);

        key = secretKeySerialization.deSerialize();
        iv = new IvParameterSpec(Files.readAllBytes(Path.of(ivFilePath)));
    }

    /**
     * Encrypts the text to cipher;
     *
     * @param text The text you want to encrypt.
     * @return Returns The cipher text.
     * @throws Exception Throws exception if operation goes wrong.
     */
    public String encrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * Decrypts cipher to plain text.
     *
     * @param cipherText The cipher you want to decrypt.
     * @return Returns the plain text.
     * @throws Exception Throws exception if operation goes wrong.
     */
    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    /**
     * Encrypts the entire file.You can't open the file after encryption has been completed.
     *
     * @param inputFile The file you want to encrypt.
     * @return Returns the file content into byte arrays.
     * @throws Exception Throws exception if operation goes wrong.
     */
    public byte[] encryptFile(File inputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(Files.readAllBytes(inputFile.toPath()));
    }

    /**
     * Decrypts the entire file.After this you can normally open the file like before.
     *
     * @param inputFile The file you want to decrypt.
     * @return Returns the file content into byte arrays.
     * @throws Exception Throws exception if operation goes wrong.
     */
    public byte[] decryptFile(File inputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(Files.readAllBytes(inputFile.toPath()));
    }

    /**
     * Generates new initialization vector.
     *
     * @return Returns the generated vector.
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Generates new secret key.
     *
     * @param n The length of AES key (128,192,256)
     * @return Returns the generated key.
     * @throws NoSuchAlgorithmException If no algorithms exist to start encryption.
     * @throws InvalidKeySpecException  This is the exception for invalid key specifications
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);

        return keyGenerator.generateKey();
    }

    /**
     * Generates backup from secret key and initialization vector to a file.
     *
     * @param folderPath The folder you want to save these files.
     * @return Returns true if operation was successful and false if not.
     * @throws IOException Throws IOException of read or writing of files goes wrong.
     */
    public boolean createBackup(String folderPath) throws IOException {
        String secretKeyPath = folderPath + "/SecretKey.dat",
                ivPath = folderPath + "/IV.dat";

        Path path = Path.of(folderPath);
        if (!Files.exists(path) || !Files.isDirectory(path)) {
            return false;
        }

        Serialization<SecretKey> secretKeySerialization = new Serialization<>(secretKeyPath, key);
        secretKeySerialization.serialize();

        Files.write(Path.of(ivPath), iv.getIV());
        return true;
    }
}
