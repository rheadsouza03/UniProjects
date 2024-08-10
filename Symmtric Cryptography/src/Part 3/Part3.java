import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.System.exit;

/**
 * Commandline based encryption and decryption program
 * @author Rhea D'Souza
 */
public class Part3 {
    private static final Logger LOG = Logger.getLogger(Part3.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String[] CIPHERS = {
            "AES/CBC/PKCS5Padding",
            "AES/ECB/PKCS5Padding",
            "AES/GCM/NoPadding",
            "AES/OFB/NoPadding",
            "AES/CFB/NoPadding"
    };
    private static final int GCM_TAG_LENGTH = 128;
    private static final int[] KEY_SIZES = {128, 192, 256}; // in bits
    private static final String[] INPUT_FILES = {"plaintext.txt", "plaintext2.txt", "plaintext3.txt", "plaintext4.txt", "plaintext5.txt"};

    public static void main(String[] args){
        Map<int[], Double> encryptionDurations = new HashMap<>();
        Map<int[], Double> decryptionDurations = new HashMap<>();

        for(int i = 0; i < INPUT_FILES.length; i++){
            for(int j = 0; j < KEY_SIZES.length; j++){
                for(int k = 0; k < CIPHERS.length; k++){
                    SecureRandom sr = new SecureRandom();

                    // Create random key
                    byte[] key = new byte[(int)( KEY_SIZES[j] / 8)]; // Default key size
                    sr.nextBytes(key);
                    SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

                    // Create random initialisation-vector
                    byte[] initVector = new byte[16];
                    sr.nextBytes(initVector);
                    IvParameterSpec iv = new IvParameterSpec(initVector);

                    // Print random values to console/command-line
                    System.out.println("Random key=" + Util.bytesToHex(key));
                    System.out.println("initVector=" + Util.bytesToHex(initVector));

                    // Get pre-initialised Cipher instance
                    String cipher = CIPHERS[k];
                    Cipher cipherEnc = getCipher(cipher, Cipher.ENCRYPT_MODE, skeySpec, iv);
                    Cipher cipherDec = getCipher(cipher, Cipher.DECRYPT_MODE, skeySpec, iv);

                    // Perform multiple iterations of encryption and decryption and collect their durations
                    double[] iterDurations = getAverageDurations(cipherEnc, cipherDec, INPUT_FILES[i]);

                    // Store collected durations
                    encryptionDurations.put(new int[]{i, j, k}, iterDurations[0]);
                    decryptionDurations.put(new int[]{i, j, k}, iterDurations[1]);
                }
            }
        }

    }

    /**
     * Gets the average duration taken to perform encryption and decryption with the given values.
     * @param cipherEnc - Cipher instance initialised for encryption
     * @param cipherDec - Cipher instance initialised for encryption
     * @param inputFile - String with the input file name
     * @return Double array with encryption average stored at index 0 and decryption stored in index 1
     */
    private static double[] getAverageDurations(Cipher cipherEnc, Cipher cipherDec, String inputFile) {
        double[] durations = {0, 0};

        for(int i = 0; i < 10; i++){
            //Perform Encryption and Decryption, and get the summation of their durations
            durations[0] += performOperation(cipherEnc, inputFile, "encryption");
            durations[1] += performOperation(cipherDec, inputFile, "decryption");
        }

        durations[0] /= 10;
        durations[1] /= 10;

        return durations;
    }

    /**
     * Gets a Cipher pre-initialised instance.
     * @param cipherMode - The encryption/decryption mode
     * @param operation - Integer indicating whether the encryption or decryption operation is performed
     * @param skeySpec - Key for the encryption/decryption
     * @param iv - Initialisation-vector for the encryption/decryption
     * @return Pre-initialised Cipher instance
     */
    private static Cipher getCipher(String cipherMode, int operation, SecretKeySpec skeySpec, IvParameterSpec iv){
        Cipher cipher = null;
        try {
            // Get appropriate cipher instance
            cipher = Cipher.getInstance(cipherMode);

            // Initialise that instance based on the type of algorithm used
            if (cipherMode.contains("GCM")) {cipher.init(operation, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));}
            else if (cipherMode.contains("ECB")){cipher.init(operation, skeySpec);}
            else {cipher.init(operation, skeySpec, iv);}

        } catch (NoSuchAlgorithmException e) {
            LOG.log(Level.SEVERE, "Algorithm not supported: " + cipherMode);
            exit(1);
        } catch (NoSuchPaddingException e) {
            LOG.log(Level.SEVERE, "No such padding: " + cipherMode);
            exit(1);
        }catch (InvalidKeyException e) {
            LOG.log(Level.SEVERE, "Invalid key. Cannot be used for encryption of this file.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.SEVERE, "Invalid algorithm. Cannot be used for encryption of this file.");
            exit(1);
        }

        return cipher;
    }


    /**
     * Decrypts the given encrypted file with the iv and key that is provided.
     * Saves to given file with ending suffix `.dec`, if output file not provided,
     * the input file is used for it's naming.
     * @param cipher - Cipher instance used to perform decryption
     * @param inputFile - file containing the encrypted/ciphertext data
     */
    private static double performOperation(Cipher cipher, String inputFile, String operation){
        try {
            // Gets the file path
            Path inputPath = Paths.get("data/"+inputFile);

            // Performs encryption/decryption and measures duration
            double start = System.currentTimeMillis();
            cipher.doFinal(Files.readAllBytes(inputPath));
            double end = System.currentTimeMillis();

            return end - start;
        } catch (IllegalBlockSizeException e) {
            LOG.severe("Unable to "+operation+": Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Unable to "+operation+": Bad padding. Cannot perform encryption.");
            exit(1);
        }catch (IOException e) {
            LOG.severe("Unable to perform "+operation+": Error occurred when reading or writing to a file.");
            exit(1);
        }

        return 0;
    }

    private static int[] getFileSizes(){
        int[] fileSizes = new int[INPUT_FILES.length];
        for(int i = 0; i < INPUT_FILES.length; i++){
            fileSizes[i] = (int) new File("data/"+INPUT_FILES[i]).length();
        }

        return fileSizes;
    }

    private static void savePerformanceMetrics(String operation, byte[] key, String mode, int fileSize, double duration) {
        String csvFile = "results.csv";
        String keyLength = Arrays.toString(Base64.getDecoder().decode(key));
        String entry = String.format("%s,%s,%d,%s,%.2f\n", operation, mode, fileSize, keyLength, duration);

        try {
            Files.write(Paths.get(csvFile), entry.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to save performance metrics to CSV", e);
            exit(1);
        }
    }

}