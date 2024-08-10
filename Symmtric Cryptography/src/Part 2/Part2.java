import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.System.exit;

/**
 * Password-based encryption/decryption with PBKDF2
 * @author Rhea D'Souza
 */
public class Part2 {
    private static final Logger LOG = Logger.getLogger(Part2.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int KEY_LENGTH = 16; // AES key length
    private static final int IV_LENGTH = 16; // AES IV length
    private static final int SALT_LENGTH = 16; // Salt length
    private static final int ITERATIONS = 10000; // PBKDF2 iterations

    public static void main(String[] args){
        if (args.length < 2 && args.length % 2 == 0) {
            LOG.severe("Insufficient arguments provided.");
            exit(1);
        }

        String operation = args[0].toLowerCase();
        String password = null;
        String inputFile = null;
        String outputFile = null;

        // Parsing command-line arguments
        List<String> options = List.of("-p", "--pass", "-i", "--input-file", "-o", "--output-file");
        for (int i = 1; i < args.length; i++) {
            if (i + 1 < args.length && options.contains(args[i])) {
                String current = args[i+1];
                if(options.contains(current)){
                    LOG.severe("Invalid argument provided." + args[i] + " and " + current + " are 2 different options.");
                    exit(1);
                }
                switch (args[i]) {
                    case "-p", "--pass" -> password = current;
                    case "-i", "--input-file"-> inputFile = current;
                    case "-o", "--output-file"-> outputFile = current;
                    default -> {
                        LOG.severe("Unrecognized argument: " + args[i]);
                        exit(1);
                    }
                }
                ++i;
            } else {
                LOG.severe("Argument " + args[i] + " is missing a value.");
                exit(1);
            }
        }

        // Checking to ensure the relevant information has been provided
        if (password == null) {
            LOG.severe("Password is required.");
            exit(1);
        }
        if (inputFile == null || outputFile == null) {
            LOG.severe("Input file and output file are required for encryption and decryption.");
            exit(1);
        }

        // Gets the cipher algorithm
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(CIPHER);
        } catch (NoSuchAlgorithmException e) {
            LOG.severe("No such algorithm: " + CIPHER);
            exit(1);
        } catch (NoSuchPaddingException e) {
            LOG.severe("No such padding: " + CIPHER);
            exit(1);
        }

        // Perform encryption or decryption
        if (operation.equals("enc")) {
            // Generates salt for the password
            SecureRandom sr = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            sr.nextBytes(salt);

            // Generates key and iv
            SecretKeySpec skeySpec = getKeyFromPassword(password, salt);
            IvParameterSpec iv = new IvParameterSpec(generateRandomIV());

            // Informs user of the generated key and iv
            System.out.println("Key length: " + skeySpec.getEncoded().length + " bytes");
            System.out.println("Generated Salt: " + Util.bytesToHex(salt));
            System.out.println("Generated IV: " + Util.bytesToHex((iv.getIV())));

            // Performs encryption
            performEncryption(cipher, salt, skeySpec, iv, inputFile, outputFile);

        } else if (operation.equals("dec")) {
            // Performs decryption
            performDecryption(cipher, password, inputFile, outputFile);
        } else {
            LOG.severe("Invalid operation. Use 'enc' for encryption or 'dec' for decryption.");
            exit(1);
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
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.log(Level.SEVERE, "Error while generating key.");
            exit(1);
        }
        return new SecretKeySpec(key, ALGORITHM);
    }

    /**
     * Generates random initialisation-vector (iv).
     * @return byte array of the randomly generated iv
     */
    private static byte[] generateRandomIV() {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        sr.nextBytes(iv);
        return iv;
    }

    /**
     * Performs the encryption on the input file with given params and writes the ciphertext to
     * the output file with a `.enc` extension.
     * @param cipher - Cipher instance
     * @param salt - Byte array of the salt
     * @param skeySpec - Secret key
     * @param iv - Initialisation vector
     * @param inputFile - input file name
     * @param outputFile - output file name
     */
    private static void performEncryption(Cipher cipher, byte[] salt, SecretKeySpec skeySpec, IvParameterSpec iv, String inputFile, String outputFile){
        // Initialise the Cipher instance to decryption mode with key and iv params
        try {cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);}
        catch (InvalidKeyException e) {
            LOG.severe("Invalid key. Cannot perform encryption.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.severe("Invalid algorithm. Cannot perform encryption.");
            exit(1);
        }

        // Get the input and output file paths
        Path inputPath = Paths.get("data/"+inputFile);
        Path outputPath = Paths.get("data/"+((outputFile.endsWith(".enc"))?outputFile:(outputFile+".enc")));

        // Convert plaintext document into byte array
        byte[] plaintext = null;
        try {
            plaintext = Files.readAllBytes(inputPath);
        } catch (IOException e) {
            LOG.severe("Cannot read input file.");
            exit(1);
        }

        // Convert plaintext -> ciphertext
        byte[] ciphertext = null;
        try {ciphertext = cipher.doFinal(plaintext);}
        catch (IllegalBlockSizeException e) {
            LOG.severe("Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Bad padding. Cannot perform encryption.");
            exit(1);
        }

        // Write the iv byte array to file, followed by the ciphertext byte array
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream()) {
            byteStream.write(salt);
            byteStream.write(iv.getIV());
            byteStream.write(ciphertext);
            byte[] finalOutput = byteStream.toByteArray();

            Files.write(outputPath, finalOutput);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to encrypt. Cannot encrypt.");
            exit(1);
        }

        // Inform user of successful encryption
        LOG.info("Encryption complete, saved at: " + outputPath);
    }

    /**
     * Perform decryption of the input file. Retrieves salt and iv from the first 32 bytes and generates the key.
     * Then writes the decrypted data to a file with the `.dec` extension.
     * @param cipher - Cipher instance
     * @param password - password provided by user
     * @param inputFile - input file name
     * @param outputFile - output file name
     */
    private static void performDecryption(Cipher cipher, String password, String inputFile, String outputFile){
        // Get the input and output file paths
        Path inputPath = Paths.get("data/" + inputFile);
        Path outputPath = Paths.get("data/" + ((outputFile.endsWith(".dec"))? outputFile : (outputFile+".dec")));

        // Read the entire file content into a byte array
        byte[] fileContent = null;
        try {
            fileContent = Files.readAllBytes(inputPath);
        } catch (IOException e) {
            LOG.severe("Cannot read input file.");
            exit(1);
        }

        // Extract the salt from the first 16 bytes of the file content
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(fileContent, 0, salt, 0, SALT_LENGTH);
        SecretKeySpec skeySpec = getKeyFromPassword(password, salt);

        // Extract the IV from the first 16 bytes of the file content
        byte[] ivBytes = new byte[IV_LENGTH];
        System.arraycopy(fileContent, SALT_LENGTH, ivBytes, 0, IV_LENGTH);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Extract the ciphertext (remaining bytes after the IV)
        byte[] ciphertext = new byte[fileContent.length - IV_LENGTH - SALT_LENGTH];
        System.arraycopy(fileContent, SALT_LENGTH + IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Initialise the Cipher instance to decryption mode with key and iv params
        try {cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);}
        catch (InvalidKeyException e) {
            LOG.severe("Invalid key. Cannot perform decryption.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.severe("Invalid algorithm. Cannot perform decryption.");
            exit(1);
        }

        // Convert ciphertext -> plaintext
        byte[] plaintext = null;
        try {plaintext = cipher.doFinal(ciphertext);}
        catch (IllegalBlockSizeException e) {
            LOG.severe("Illegal block size. Cannot perform decryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Bad padding. Cannot perform decryption.");
            exit(1);
        }

        // Writes the decrypted plaintext to the output file
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream();) {
            byteStream.write(plaintext);
            byte[] finalOutput = byteStream.toByteArray();

            Files.write(outputPath, finalOutput);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to encrypt. Cannot decrypt.");
            exit(1);
        }

        // Inform user of successful decryption
        LOG.info("Decryption complete, saved at " + outputPath);
    }

}
