import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 */
public class Part1 {
    private static final Logger LOG = Logger.getLogger(Part1.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        // Handling commandline arguments
        if(args.length < 2) {LOG.log(Level.SEVERE, "Input file is required. Cannot perform operation.");}
        String encOrDec = args[0].toLowerCase();
        Map<String, String> arguments = parseArgs(args);

        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        SecretKeySpec skeySpec = (arguments.containsKey("key")||encOrDec.equals("enc"))?
                                         getOrCreateKey(arguments, sr):null;
        IvParameterSpec iv = (arguments.containsKey("initialisation-vector")||encOrDec.equals("enc"))?
                                      getOrCreateIv(arguments, sr):null;

        // Check to ensure decryption operation has a key and iv specified
        if (encOrDec.equals("dec") && (skeySpec == null || iv == null)) {
            LOG.log(Level.SEVERE, "Decryption requirement not met. No initialisation-vector and/or key specified.");
            return;
        }

        // Gets mode of Cipher
        Cipher cipher = Cipher.getInstance(arguments.getOrDefault("mode", CIPHER));

        //Perform Encryption or Decryption
        if(encOrDec.equals("enc")) {performEncryption(cipher, iv, skeySpec, arguments);}
        else if(encOrDec.equals("dec")) {performDecryption(cipher, iv, skeySpec, arguments);}
        else{ LOG.log(Level.SEVERE, "Unrecognized mode. Use 'ENC' for encryption or 'DEC' for decryption");}
    }

    /**
     *
     * @param cipher
     * @param iv
     * @param skeySpec
     * @param arguments
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    private static void performDecryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, Map<String, String> arguments) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        final Path tempDir =Files.createTempDirectory("packt-crypto"); // recently added
        final Path decryptedPath = tempDir.resolve("1 - Encrypting and Decrypting files_decrypted.pptx");
        try(InputStream encryptedData = Files.newInputStream(Path.of(arguments.getOrDefault("input-file", null)));
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(Path.of(arguments.getOrDefault("output-file", null)))){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(Part1.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

    /**
     *
     * @param cipher
     * @param iv
     * @param skeySpec
     * @param arguments
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    private static void performEncryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, Map<String, String> arguments) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        //Look for files here
        final Path tempDir = Files.createTempDirectory("packt-crypto");

        final Path encryptedPath = tempDir.resolve("1 - Encrypting and Decrypting files.pptx.encrypted");
        try (InputStream fin = Part1.class.getResourceAsStream("1 - Encrypting and Decrypting files.pptx");
             OutputStream fout = Files.newOutputStream(Path.of(arguments.getOrDefault("output-file", null)));
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            final byte[] bytes = new byte[1024];
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    /**
     * Gets the provided key, if present. Otherwise, randomly generates a key.
     * @param arguments - a map of the command-line arguments
     * @param sr - the secure random instance
     * @return the secret key spec is returned.
     */
    private static SecretKeySpec getOrCreateKey(Map<String, String> arguments, SecureRandom sr) {
        byte[] key = new byte[16];
        if(arguments.containsKey("key")) {
            key = arguments.get("key").getBytes();
            System.out.println("Given key=" + Util.bytesToHex(key));
        }
        else{
            sr.nextBytes(key); // 128 bit key
            System.out.println("Random key=" + Util.bytesToHex(key));
        }

        saveBase64File(key, "key.base64"); // Saves the key byte data

        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        return skeySpec;
    }

    /**
     * Gets the specified initialisation-vector (IV), if present. Otherwise, randomly generates an IV.
     * @param arguments - map of commandline arguments
     * @param sr - secure random instance
     * @return iv parameter of the random generation or specified key is returned
     */
    private static IvParameterSpec getOrCreateIv(Map<String, String> arguments, SecureRandom sr) {
        byte[] initVector = new byte[16];
        if(arguments.containsKey("initialisation-vector")) {
            initVector = arguments.get("initialisation-vector").getBytes();
            System.out.println("Given initVector=" + Util.bytesToHex(initVector));
        }
        else{
            sr.nextBytes(initVector); // 16 bytes IV
            System.out.println("Random initVector=" + Util.bytesToHex(initVector));
        }

        saveBase64File(initVector, "iv.base64"); // Saves the iv byte data

        IvParameterSpec iv = new IvParameterSpec(initVector);
        return iv;
    }

    /**
     * Creates a Base64 file by converting the given byte data. Data is saved to a file with the given filename.
     * @param data - byte data that is to be converted to base64 and saved
     * @param filename - name of file data is saved to
     */
    private static void saveBase64File(byte[] data, String filename) {
        try {Files.write(Paths.get(filename), Base64.getEncoder().encode(data));}
        catch (IOException e) {throw new RuntimeException(e);}
    }

    /**
     * Takes and saves the command line args in a map using their more descriptive keywords.
     * @param args - commandline arguments
     * @return map of command line arguments
     */
    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> params = new HashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (i + 1 < args.length) {
                String key = switch (args[i]) {
                    case "--input-file", "-i" -> "input-file";
                    case "--output-file", "-o" -> "output-file";
                    case "--mode", "-m" -> "mode";
                    case "--initialisation-vector", "-iv" -> "initialisation-vector";
                    case "--key-file", "-k" -> "key";
                    default -> null;
                };
                String value = args[i + 1];
                params.put(key, value);
            } else {
                LOG.severe("Argument " + args[i] + " is missing a value.");
            }
        }
        return params;
    }
}