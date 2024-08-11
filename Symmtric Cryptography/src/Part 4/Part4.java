import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.System.exit;

/**
 * @author Rhea D'Souza
 * UID: dsouzrhea
 */
public class Part4 {
    private static final Logger LOG = Logger.getLogger(Part4.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int KEY_LENGTH = 16; // AES key length
    private static final int IV_LENGTH = 16; // AES IV length
    private static final int SALT_LENGTH = 16; // Salt length
    private static final int ITERATIONS = 10000; // PBKDF2 iterations

    public static void main(String[] args) {
        if (args.length != 3) {
            LOG.severe("Usage: java Part4 <ciphertext-file> -t <type>");
            System.exit(1);
        }

        String ciphertextFile = args[0];
        int type = Integer.parseInt(args[2]);

        // Set charset based on the type
        String charset;
        switch (type) {
            case 0:
                charset = "abcdefghijklmnopqrstuvwxyz";
                break;
            case 1:
                charset = "abcdefghijklmnopqrstuvwxyz0123456789";
                break;
            case 2:
                charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                break;
            default:
                LOG.severe("Invalid type. Use 0, 1, or 2.");
                System.exit(1);
                return;
        }

        try {
            // Read ciphertext
            System.out.println("========================\nReading ciphertext file: \n========================");
            Path path = Paths.get("data/testCiphertexts/"+ciphertextFile);
            byte[] ciphertext = Files.readAllBytes(path);

            // Extract salt and IV from the ciphertext
            byte[] salt = new byte[SALT_LENGTH];
            System.arraycopy(ciphertext, 0, salt, 0, SALT_LENGTH);
            LOG.info("Salt has successfully been read.");

            byte[] ivBytes = new byte[IV_LENGTH];
            System.arraycopy(ciphertext, SALT_LENGTH, ivBytes, 0, IV_LENGTH);
            LOG.info("Initialisation vector has successfully been read.");

            byte[] actualCiphertext = new byte[ciphertext.length - SALT_LENGTH - IV_LENGTH];
            System.arraycopy(ciphertext, SALT_LENGTH + IV_LENGTH, actualCiphertext, 0, actualCiphertext.length);
            LOG.info("ciphertext has successfully been read.");

            // Brute-force password search
            LOG.info("Brute-forcing in process...");

                // Begin bruteforce and timing
            long startTime = System.currentTimeMillis();
            String password = bruteForce(charset, salt, ivBytes, actualCiphertext);
            long endTime = System.currentTimeMillis();
            float durationMs = endTime - startTime;

                // Formatting durations
            String formattedDurationMs = String.format("%.2f", durationMs);
            String formattedDurationSec = String.format("%.2f", (durationMs/1000));

                // Indicate that brute force has been completed
            LOG.info("Brute-force completed.");

                // Show the results on the commandline
            LOG.info("Brute-force results: ");
            if (password != null) {
                System.out.println("    *  Password: "+ password);
                System.out.println("    *  Password found in " + formattedDurationMs + " ms (" + formattedDurationSec + " secs)");
            } else {
                LOG.severe("Password not found.");
            }
        } catch (IOException e) {
            LOG.severe("Failed to read ciphertext file.");
            System.exit(1);
        }
    }

    private static String bruteForce(String charset, byte[] salt, byte[] iv, byte[] actualCiphertext) {
        int maxPasswordLength = 6;
        char[] password = new char[maxPasswordLength];

        return generatePasswords(charset, password, 0, salt, iv, actualCiphertext);
    }

    private static String generatePasswords(String charset, char[] password, int position, byte[] salt, byte[] iv, byte[] actualCiphertext) {
        if (position == password.length) {
            String pwd = new String(password);
            if (testPassword(pwd, salt, iv, actualCiphertext)) {return pwd;}
            return null;
        }

        for (char c : charset.toCharArray()) {
            password[position] = c;
            String result = generatePasswords(charset, password, position + 1, salt, iv, actualCiphertext);
            if (result != null) {return result;}
        }
        return null;
    }

    private static boolean testPassword(String password, byte[] salt, byte[] iv, byte[] actualCiphertext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            SecretKeySpec keySpec = getKeyFromPassword(password, salt);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] decryptedText = cipher.doFinal(actualCiphertext);

            // Check if the decrypted text is valid (this might need adjustment based on your ciphertext content)
            String decryptedString = new String(decryptedText, StandardCharsets.UTF_8);
            return decryptedString.startsWith("This is an example");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generate a secret key using the provided salt and password.
     * @param password - inputted password given by the user
     * @param salt - randomly generated salt
     * @return Resulting secret key of the provided salt and password
     */
    private static SecretKeySpec getKeyFromPassword(String password, byte[] salt){
        byte[] key = new byte[KEY_LENGTH];
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH*8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            key = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.log(Level.SEVERE, "Error while generating key.");
            exit(1);
        }
        return new SecretKeySpec(key, ALGORITHM);
    }
}
