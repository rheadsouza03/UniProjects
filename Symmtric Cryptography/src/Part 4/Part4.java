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
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.System.exit;

public class Part4 {
    private static final Logger LOG = Logger.getLogger(Part4.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int KEY_LENGTH = 16; // AES key length
    private static final int IV_LENGTH = 16; // AES IV length
    private static final int SALT_LENGTH = 16; // Salt length
    private static final int ITERATIONS = 10000; // PBKDF2 iterations
    private static final int PASS_LENGTH_LIM = 6; // Password length limit iterations
    private static final String PLAINTEXT_PREFIX_VALIDATION = "This is an example"; // expected prefix of plaintext

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
        LOG.info("Charset type has been set to: \"" + charset + "\"");

        try {
            LOG.info("Reading from file...");
            // Read ciphertext
            Path path = Paths.get("data/testCiphertexts/"+ciphertextFile);
            byte[] file = Files.readAllBytes(path);

            // Extract salt and IV from the ciphertext
            byte[] salt = new byte[SALT_LENGTH];
            System.arraycopy(file, 0, salt, 0, SALT_LENGTH);
            LOG.info("Salt has been extracted successfully.");

            byte[] ivBytes = new byte[IV_LENGTH];
            System.arraycopy(file, SALT_LENGTH, ivBytes, 0, IV_LENGTH);
            LOG.info("IV has been extracted successfully.");

            byte[] ciphertext = new byte[file.length - SALT_LENGTH - IV_LENGTH];
            System.arraycopy(file, SALT_LENGTH + IV_LENGTH, ciphertext, 0, ciphertext.length);
            LOG.info("Ciphertext has been extracted successfully.\nFile has been closed, reading complete.");

            // Brute-force password search
            LOG.info("Brute-forcing has started...");
            long startTime = System.currentTimeMillis();
            String password = bruteForce(charset, salt, ivBytes, ciphertext);
            long endTime = System.currentTimeMillis();
            float durationMs = endTime - startTime;
            LOG.info("Brute-forcing has stopped.");

            LOG.info("Results: \n");
            if (password != null) {
                System.out.println("Password Found: "+password);  // Print the password as per the requirement.
                System.out.println("Duration: "+durationMs + "ms");
            } else {
                LOG.severe("Password not found.");
                exit(1);
            }
        } catch (IOException e) {
            LOG.severe("Failed to read ciphertext file.");
            System.exit(1);
        }
    }

    /**
     * Performs password creation using the exhaustive search method (brute-force)
     * @param charset - valid password character set
     * @param salt - random salt from file
     * @param ivBytes - iv from ciphertext file
     * @param ciphertext - encrypted data from file
     * @return String of the password, if found and validated. Otherwise, null if password cannot be found.
     */
    private static String bruteForce(String charset, byte[] salt, byte[] ivBytes, byte[] ciphertext) {
        char[] password = new char[PASS_LENGTH_LIM];
        int charsetLength = charset.length();

        // Loop over all possible password lengths from 1 to PASS_LENGTH_LIM
        for (int length = 1; length <= PASS_LENGTH_LIM; length++) {
            // Initialize the indices array to keep track of current position in charset
            int[] indices = new int[length];

            while (true) {
                // Build the current password based on the indices array
                for (int i = 0; i < length; i++) {
                    password[i] = charset.charAt(indices[i]);
                }

                // Test the current password
                String currentPassword = new String(password, 0, length);
                if (testPassword(currentPassword, salt, ivBytes, ciphertext)) {
                    return currentPassword; // Return the password when found
                }

                // Update the indices to generate the next password
                int position = length - 1;
                while (position >= 0) {
                    if (indices[position] < charsetLength - 1) {
                        indices[position]++;
                        break;
                    } else {
                        indices[position] = 0;
                        position--;
                    }
                }

                // If we've reset all positions back to 0, exit the loop for this length
                if (position < 0) {break;}
            }
        }

        return null; // Return null if no password is found
    }


    /**
     * Decrypts ciphertext with given parameters and verifies the password against the expected decrypted prefix.
     * @param password - brute-forced password that is being checked
     * @param salt - random salt that is stored in the encrypted file
     * @param iv - initialisation vector that is stored in the encrypted file
     * @param ciphertext - encrypted data
     * @return
     */
    private static boolean testPassword(String password, byte[] salt, byte[] iv, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            SecretKeySpec keySpec = getKeyFromPassword(password, salt);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] decryptedText = cipher.doFinal(ciphertext);

            // Check if the decrypted text is valid (this might need adjustment based on your ciphertext content)
            String decryptedString = new String(decryptedText, StandardCharsets.UTF_8);
            return decryptedString.startsWith(PLAINTEXT_PREFIX_VALIDATION);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Gets the key using the PBEKeySpec with the password and salt as params
     * @param password - brute-forced password
     * @param salt - random salt
     * @return key instance resulting from the salt and password.
     */
    private static SecretKeySpec getKeyFromPassword(String password, byte[] salt) {
        byte[] key = new byte[KEY_LENGTH];
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            key = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.log(Level.SEVERE, "Error while generating key.");
            exit(1);
        }
        return new SecretKeySpec(key, ALGORITHM);
    }
}
