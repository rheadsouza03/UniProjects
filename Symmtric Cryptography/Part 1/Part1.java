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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.System.exit;

/**
 * Commandline based encryption and decryption program
 * @author Rhea D'Souza
 */
public class Part1 {
    private static final Logger LOG = Logger.getLogger(Part1.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int GCM_TAG_LENGTH = 128;
    private static int ivIncrement = 0;
    private static int keyIncrement = 0;

    public static void main(String[] args){
        // Handling commandline arguments
        if(args.length < 2) {
            LOG.log(Level.SEVERE, "Input file is required. Cannot perform operation.");
            exit(1);
        }
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
            exit(1);
        }

        // Gets mode of Cipher
        String cipherMode = arguments.getOrDefault("mode", CIPHER);
        if(cipherMode.equals("GCM") || cipherMode.equals("CFB") || cipherMode.equals("OFB")) {
            cipherMode = "AES/"+cipherMode+"/NoPadding";
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherMode);
        } catch (NoSuchAlgorithmException e) {
            LOG.log(Level.SEVERE, "Algorithm not supported: " + cipherMode, e);
            exit(1);
        } catch (NoSuchPaddingException e) {
            LOG.log(Level.SEVERE, "No such padding: " + cipherMode, e);
            exit(1);
        }

        //Perform Encryption or Decryption
        if(encOrDec.equals("enc")) {performEncryption(cipher, iv, skeySpec, arguments, cipherMode);}
        else if(encOrDec.equals("dec")) {performDecryption(cipher, iv, skeySpec, arguments, cipherMode);}
        else{
            LOG.log(Level.SEVERE, "Unrecognized mode. Use 'ENC' for encryption or 'DEC' for decryption");
            exit(1);
        }
    }

    /**
     *
     * @param cipher
     * @param iv
     * @param skeySpec
     * @param arguments
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    private static void performDecryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, Map<String, String> arguments, String cipherMode){
        try {
            if (cipherMode.contains("GCM")) {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            }
        }catch (InvalidKeyException e) {
            LOG.log(Level.SEVERE, "Invalid key. Cannot be used for decryption of this file.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.SEVERE, "Invalid algorithm. Cannot be used for decryption of this file.");
            exit(1);
        }
        Path inputPath = Paths.get(arguments.getOrDefault("input-file", null));
        String outputFile = arguments.getOrDefault("output-file", inputPath.toString().replace(".enc", ""));
        Path outputPath = Paths.get(((outputFile.endsWith(".dec"))?outputFile:(outputFile+".dec")));

        try (InputStream encryptedData = Files.newInputStream(inputPath);
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
             OutputStream decryptedOut = Files.newOutputStream(outputPath)) {
            byte[] bytes = new byte[1024];
            int length;
            while ((length = decryptStream.read(bytes)) != -1) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, "Unable to decrypt", ex);
            exit(1);
        }

        LOG.info("Decryption complete, saved at " + outputPath);
    }

    /**
     *
     * @param cipher
     * @param iv
     * @param skeySpec
     * @param arguments
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    private static void performEncryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, Map<String, String> arguments, String cipherMode){
        try {
            if (cipherMode.contains("GCM")) {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            }
        }catch (InvalidKeyException e) {
            LOG.log(Level.SEVERE, "Invalid key. Cannot be used for encryption of this file.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.SEVERE, "Invalid algorithm. Cannot be used for encryption of this file.");
            exit(1);
        }

        Path inputPath = Paths.get(arguments.getOrDefault("input-file", null));
        String outputFile = arguments.getOrDefault("output-file", inputPath.toString());
        Path outputPath = Paths.get(((outputFile.endsWith(".enc"))?outputFile:(outputFile+".enc")));

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
            exit(1);
        }

        LOG.info("Encryption completed, saved at " + outputPath);
    }

    /**
     * Gets the provided key, if present. Otherwise, randomly generates a key.
     * @param arguments - a map of the command-line arguments
     * @param sr - the secure random instance
     * @return the secret key spec is returned.
     */
    private static SecretKeySpec getOrCreateKey(Map<String, String> arguments, SecureRandom sr){
        byte[] key = new byte[16]; // Default key size
        if (arguments.containsKey("key")) {
            Path keyPath = Paths.get(arguments.get("key"));
            try {
                key = Base64.getDecoder().decode(Files.readAllBytes(keyPath));
            } catch (IOException e) {
                LOG.log(Level.SEVERE, "Unable to read key or file "+arguments.get("key")+" does not exist.");
                exit(1);
            }
            if (key.length != 16 && key.length != 24 && key.length != 32) {
                LOG.log(Level.SEVERE, "Invalid AES key length: " + key.length + " bytes. Must be 16, 24, or 32 bytes.");
                exit(1);
            }
            System.out.println("Given key=" + Util.bytesToHex(key));
        } else {
            sr.nextBytes(key); // 128 bit key
            System.out.println("Random key=" + Util.bytesToHex(key));
            saveBase64File(key, "key"+((keyIncrement==0)?"":keyIncrement)+".base64");
            ++keyIncrement;
        }

        return new SecretKeySpec(key, ALGORITHM);
    }

    /**
     * Gets the specified initialisation-vector (IV), if present. Otherwise, randomly generates an IV.
     * @param arguments - map of commandline arguments
     * @param sr - secure random instance
     * @return iv parameter of the random generation or specified key is returned
     */
    private static IvParameterSpec getOrCreateIv(Map<String, String> arguments, SecureRandom sr) {
        byte[] initVector = new byte[16];
        if (arguments.containsKey("initialisation-vector")) {
            Path ivPath = Paths.get(arguments.get("initialisation-vector"));
            try {
                initVector = Base64.getDecoder().decode(Files.readAllBytes(ivPath));
            } catch (IOException e) {
                LOG.log(Level.SEVERE, "Unable to read initialisation-vector or file \'"+ arguments.get("initialisation-vector") +"\' does not exist");
                exit(1);
            }
            if (initVector.length != 16) {
               LOG.log(Level.SEVERE, "Invalid IV length: " + initVector.length + " bytes. Must be 16 bytes.");
                exit(1);
            }
            System.out.println("Given initVector=" + Util.bytesToHex(initVector));
            LOG.log(Level.INFO, "IV has been successfully generated.");
        } else {
            sr.nextBytes(initVector); // 16 bytes IV
            System.out.println("Random initVector=" + Util.bytesToHex(initVector));
            saveBase64File(initVector, "iv"+((ivIncrement==0)?"":ivIncrement)+".base64");
            ++ivIncrement;
        }

        return new IvParameterSpec(initVector);
    }

    /**
     * Creates a Base64 file by converting the given byte data. Data is saved to a file with the given filename.
     * @param data - byte data that is to be converted to base64 and saved
     * @param filename - name of file data is saved to
     */
    private static void saveBase64File(byte[] data, String filename) {
        try {Files.write(Paths.get(filename), Base64.getEncoder().encode(data));}
        catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to save data to "+filename);
            exit(1);
        }
        LOG.log(Level.INFO, "Successfully created base64 file. Saved to: " + filename);
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
                exit(1);
            }
        }
        return params;
    }
}