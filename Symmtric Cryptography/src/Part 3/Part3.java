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
    private static final List<String> CIPHERS = List.of(
            "AES/CBC/PKCS5Padding",
            "AES/ECB/PKCS5Padding",
            "AES/GCM/NoPadding",
            "AES/OFB/NoPadding",
            "AES/CFB/NoPadding"
    );
    private static final int GCM_TAG_LENGTH = 128;
    private static final int[] KEY_SIZES = {128, 192, 256}; // in bits

    public static void main(String[] args){
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[(int)(KEY_SIZES[0]/8)]; // Default key size
        sr.nextBytes(key);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        byte[] initVector = new byte[16];
        sr.nextBytes(initVector);
        IvParameterSpec iv = new IvParameterSpec(initVector);

        System.out.println("Random key=" + Util.bytesToHex(key));
        System.out.println("initVector=" + Util.bytesToHex(initVector));

        // Gets mode of Cipher
        String cipherMode = CIPHERS.get(0);

        // Get pre-initialised Cipher instance
        Cipher cipherEnc = getCipher(cipherMode, Cipher.ENCRYPT_MODE, skeySpec, iv);
        Cipher cipherDec = getCipher(cipherMode, Cipher.DECRYPT_MODE, skeySpec, iv);

        //Perform Encryption or Decryption
        performEncryption(cipherEnc, iv, skeySpec, "plaintext.txt", cipherMode);
        performDecryption(cipherDec, iv, skeySpec, "plaintext.txt", cipherMode);
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
     * @param iv - Initialisation-vector that was mandatory to provide
     * @param skeySpec - Key that was mandatory to provide
     * @param inputFile - file containing the encrypted/ciphertext data
     */
    private static void performDecryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, String inputFile, String cipherMode){
        try {
            if (cipherMode.contains("GCM")) {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));
            }
            else if (cipherMode.contains("ECB")){cipher.init(Cipher.DECRYPT_MODE, skeySpec);}
            else {cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);}

            // Gets the file path
            Path inputPath = Paths.get("data/"+inputFile);

            // Decrypting: ciphertext -> plaintext
            byte[] ciphertext = cipher.doFinal(Files.readAllBytes(inputPath));

        }catch (InvalidKeyException e) {
            LOG.log(Level.SEVERE, "Invalid key. Cannot be used for decryption of this file.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.SEVERE, "Invalid algorithm. Cannot be used for decryption of this file.");
            exit(1);
        }catch (IllegalBlockSizeException e) {
            LOG.severe("Unable to decrypt: Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Unable to decrypt: Bad padding. Cannot perform encryption.");
            exit(1);
        }catch (IOException e) {
            LOG.severe("Unable to decrypt: Error occurred when reading or writing to a file.");
            exit(1);
        }
    }

    /**
     * Encrypts the input-file and saves the ciphertext to the given output file.
     * Otherwise, creates an output file using the input file as its prefix.
     * @param cipher - Cipher instance for encryption
     * @param iv - Initialisation vector
     * @param skeySpec - Secret key spec
     * @param inputFile - the file that containing the plaintext data
     */
    private static void performEncryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, String inputFile, String cipherMode){
        try {
            // Appropriately initialise cipher instance
            if (cipherMode.contains("GCM")) {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));
            }
            else if (cipherMode.contains("ECB")){cipher.init(Cipher.ENCRYPT_MODE, skeySpec);}
            else {cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);}

            // Gets the file path
            Path inputPath = Paths.get("data/"+inputFile);

            // Encrypting: plaintext -> ciphertext
            byte[] ciphertext = cipher.doFinal(Files.readAllBytes(inputPath));

        }catch (InvalidKeyException e) {
            LOG.log(Level.SEVERE, "Invalid key. Cannot be used for encryption of this file.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.SEVERE, "Invalid algorithm. Cannot be used for encryption of this file.");
            exit(1);
        }catch (IllegalBlockSizeException e) {
            LOG.severe("Unable to encrypt: Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Unable to encrypt: Bad padding. Cannot perform encryption.");
            exit(1);
        }catch (IOException e) {
            LOG.severe("Unable to encrypt: Error occurred when reading or writing to a file.");
            exit(1);
        }
    }

    /**
     * Looks through the .base64 files in the directory with the matching prefix. Aims to find a pattern match and
     * use the number in the file to determine the next increment for a new .base64 file.
     * @param prefix - file prefix
     * @return Integer related to the number of files with the given prefix in the current directory
     */
    private static int getMaxIncrement(String prefix) {
        File directory = new File("./data/");
        File[] files = directory.listFiles((_, name) -> name.startsWith(prefix) && name.endsWith(".base64"));

        if (files == null || files.length == 0) {
            return 0;
        }

        Pattern pattern = Pattern.compile("^"+prefix + "(\\d+)" + "\\.base64$");
        int maxIncrement = 0;

        for (File file : files) {
            Matcher matcher = pattern.matcher(file.getName());
            if (matcher.matches()) {
                String match = matcher.group(1);
                int increment = Integer.parseInt(match);
                if (increment > maxIncrement) {
                    maxIncrement = increment;
                }
            }
        }

        return maxIncrement+1;
    }

    private static void savePerformanceMetrics(String operation, byte[] key, String mode, long duration) {
        String csvFile = "results.csv";
        String keyLength = String.valueOf(Base64.getDecoder().decode(key));
        String fileSize = String.valueOf(new File("data/plaintext.txt").length());
        String entry = String.format("%s,%s,%s,%s,%d\n", operation, mode, fileSize, keyLength, duration);

        try {
            Files.write(Paths.get(csvFile), entry.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to save performance metrics to CSV", e);
            exit(1);
        }
    }

}