import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Password-based encryption/decryption with PBKDF2
 * @author Erik Costlow
 */
public class Part2 {
    private static final Logger LOG = Logger.getLogger(Part2.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int KEY_LENGTH = 128; // AES key length
    private static final int IV_LENGTH = 16; // AES IV length
    private static final int SALT_LENGTH = 16; // Salt length
    private static final int ITERATIONS = 10000; // PBKDF2 iterations

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            LOG.severe("Insufficient arguments provided.");
            System.exit(1);
        }

        String operation = args[0].toLowerCase();
        String password = null;
        String inputFile = null;
        String outputFile = null;

        // Parsing command-line arguments
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "-p":
                case "--pass":
                    password = args[++i];
                    break;
                case "-i":
                case "--input-file":
                    inputFile = args[++i];
                    break;
                case "-o":
                case "--output-file":
                    outputFile = args[++i];
                    break;
                default:
                    LOG.severe("Unrecognized argument: " + args[i]);
                    System.exit(1);
            }
        }

        if (password == null) {
            LOG.severe("Password is required.");
            System.exit(1);
        }

        // Generate key and IV from the password
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        sr.nextBytes(salt);

        SecretKeySpec skeySpec = getKeyFromPassword(password, salt);
        IvParameterSpec iv = new IvParameterSpec(generateRandomIV());

        System.out.println("Generated Key: " + Base64.getEncoder().encodeToString(skeySpec.getEncoded()));
        System.out.println("Generated IV: " + Base64.getEncoder().encodeToString(iv.getIV()));

        Cipher cipher = Cipher.getInstance(CIPHER);

        // Perform encryption or decryption
        if (operation.equals("enc")) {
            if (inputFile == null || outputFile == null) {
                LOG.severe("Input file and output file are required for encryption.");
                System.exit(1);
            }
            performEncryption(cipher, skeySpec, iv, inputFile, outputFile);
        } else if (operation.equals("dec")) {
            if (inputFile == null || outputFile == null) {
                LOG.severe("Input file and output file are required for decryption.");
                System.exit(1);
            }
            performDecryption(cipher, skeySpec, iv, inputFile, outputFile);
        } else {
            LOG.severe("Invalid operation. Use 'enc' for encryption or 'dec' for decryption.");
            System.exit(1);
        }
    }

    private static SecretKeySpec getKeyFromPassword(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, ALGORITHM);
    }

    private static byte[] generateRandomIV() {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        sr.nextBytes(iv);
        return iv;
    }

    private static void performEncryption(Cipher cipher, SecretKeySpec skeySpec, IvParameterSpec iv, String inputFile, String outputFile) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        Path inputPath = Path.of(inputFile);
        Path outputPath = Path.of(outputFile);

        try (InputStream fin = Files.newInputStream(inputPath);
             OutputStream fout = Files.newOutputStream(outputPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {

            byte[] bytes = new byte[1024];
            int length;
            while ((length = fin.read(bytes)) != -1) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to encrypt", e);
        }
        LOG.info("Encryption complete, saved at " + outputPath);
    }

    private static void performDecryption(Cipher cipher, SecretKeySpec skeySpec, IvParameterSpec iv, String inputFile, String outputFile) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        Path inputPath = Path.of(inputFile);
        Path outputPath = Path.of(outputFile);

        try (InputStream encryptedData = Files.newInputStream(inputPath);
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
             OutputStream decryptedOut = Files.newOutputStream(outputPath)) {

            byte[] bytes = new byte[1024];
            int length;
            while ((length = decryptStream.read(bytes)) != -1) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to decrypt", e);
        }
        LOG.info("Decryption complete, saved at " + outputPath);
    }
}
