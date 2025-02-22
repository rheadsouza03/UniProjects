import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.System.exit;

/**
 * Commandline based encryption and decryption program
 * @author Rhea D'Souza
 * UID: dsouzrhea
 */
public class Part1 {
    private static final Logger LOG = Logger.getLogger(Part1.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int KEY_SIZE = 128; // in bits

    public static void main(String[] args){
        // Handling commandline arguments
        if(args.length < 2) {
            LOG.log(Level.SEVERE, "Input file is required. Cannot perform operation.");
            exit(1);
        }
        String encOrDec = args[0].toLowerCase();
        Map<String, String> arguments = parseArgs(args);

        System.out.println("\n====================================\nStarting "+ encOrDec+"ryption processes:\n====================================");

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
        if(cipherMode.equals("GCM") || cipherMode.equals("CFB") || cipherMode.equals("OFB") || cipherMode.equals("CTR")) {
            cipherMode = "AES/"+cipherMode+"/NoPadding";
        }
        else if(cipherMode.equals("CBC") || cipherMode.equals("ECB")){
            cipherMode = "AES/"+cipherMode+"/PKCS5PADDING";
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherMode);
        } catch (NoSuchAlgorithmException e) {
            LOG.log(Level.SEVERE, "Algorithm not supported: " + cipherMode);
            exit(1);
        } catch (NoSuchPaddingException e) {
            LOG.log(Level.SEVERE, "No such padding: " + cipherMode);
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
     * Decrypts the given encrypted file with the iv and key that is provided.
     * Saves to given file with ending suffix `.dec`, if output file not provided,
     * the input file is used for it's naming.
     * @param cipher - Cipher instance used to perform decryption
     * @param iv - Initialisation-vector that was mandatory to provide
     * @param skeySpec - Key that was mandatory to provide
     * @param arguments - Commandline arguments mapped to their keywords
     */
    private static void performDecryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, Map<String, String> arguments, String cipherMode){
        try {
            if (cipherMode.contains("GCM")) {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));
            } else if (cipherMode.contains("ECB")){
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            }else {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            }
        }catch (InvalidKeyException e) {
            LOG.log(Level.SEVERE, "Invalid key. Cannot be used for decryption of this file.");
            exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.SEVERE, "Invalid algorithm. Cannot be used for decryption of this file.");
            exit(1);
        }

        String inputFile = arguments.getOrDefault("input-file", null);
        Path inputPath = Paths.get("data/"+inputFile);
        String outputFile = arguments.getOrDefault("output-file", inputFile.replace(".enc", ""));
        Path outputPath = Paths.get("data/"+((outputFile.endsWith(".dec"))?outputFile:(outputFile+".dec")));

        byte[] ciphertext = new byte[1024];
        try{
            // Decrypting: ciphertext -> plaintext
            ciphertext = cipher.doFinal(Files.readAllBytes(inputPath));

            // Begin writing to file
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byteStream.write(ciphertext);
            byte[] finalOutput = byteStream.toByteArray();
            Files.write(outputPath, finalOutput);

        } catch (IllegalBlockSizeException e) {
            LOG.severe("Unable to decrypt: Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Unable to decrypt: Bad padding. Cannot perform encryption.");
            exit(1);
        }catch (IOException e) {
            LOG.severe("Unable to decrypt: Error occurred when reading or writing to a file.");
            exit(1);
        }

        LOG.info("Decryption complete, saved at " + outputPath + "\n");
    }

    /**
     * Encrypts the input-file and saves the ciphertext to the given output file.
     * Otherwise, creates an output file using the input file as its prefix.
     * @param cipher - Cipher instance for encryption
     * @param iv - Initialisation vector
     * @param skeySpec - Secret key spec
     * @param arguments - Commandline arguments mapped to their keywords
     */
    private static void performEncryption(Cipher cipher, IvParameterSpec iv, SecretKeySpec skeySpec, Map<String, String> arguments, String cipherMode){
        try {
            if (cipherMode.contains("GCM")) {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV()));
            } else if (cipherMode.contains("ECB")){
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
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

        String inputFile = arguments.getOrDefault("input-file", null);
        Path inputPath = Paths.get("data/"+inputFile);
        String outputFile = arguments.getOrDefault("output-file", inputFile);
        Path outputPath = Paths.get("data/"+((outputFile.endsWith(".enc"))?outputFile:(outputFile+".enc")));

        byte[] ciphertext = null;
        try{
            // Encrypting: plaintext -> ciphertext
            ciphertext = cipher.doFinal(Files.readAllBytes(inputPath));

            // Begin writing to file
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byteStream.write(ciphertext);
            byte[] finalOutput = byteStream.toByteArray();
            Files.write(outputPath, finalOutput);

        } catch (IllegalBlockSizeException e) {
            LOG.severe("Unable to encrypt: Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Unable to encrypt: Bad padding. Cannot perform encryption.");
            exit(1);
        }catch (IOException e) {
            LOG.severe("Unable to encrypt: Error occurred when reading or writing to a file.");
            exit(1);
        }

        LOG.info("Encryption completed, saved at " + outputPath + "\n");
    }

    /**
     * Gets the provided key, if present. Otherwise, randomly generates a key.
     * @param arguments - A map of the command-line arguments
     * @param sr - The secure random instance
     * @return The secret key spec is returned.
     */
    private static SecretKeySpec getOrCreateKey(Map<String, String> arguments, SecureRandom sr){
        byte[] key = new byte[(int)(KEY_SIZE/8)]; // Default key size
        if (arguments.containsKey("key")) {
            Path keyPath = Paths.get("data/"+arguments.get("key"));
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
            int keyIncrement = getMaxIncrement("key");
            saveBase64File(key, "key"+((keyIncrement==0)?"":keyIncrement)+".base64");
        }

        return new SecretKeySpec(key, ALGORITHM);
    }

    /**
     * Gets the specified initialisation-vector (IV), if present. Otherwise, randomly generates an IV.
     * @param arguments - Map of commandline arguments
     * @param sr - Secure random instance
     * @return IV parameter of the random generation or specified key is returned
     */
    private static IvParameterSpec getOrCreateIv(Map<String, String> arguments, SecureRandom sr) {
        byte[] initVector = new byte[16];
        if (arguments.containsKey("initialisation-vector")) {
            Path ivPath = Paths.get("data/"+arguments.get("initialisation-vector"));
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
            int ivIncrement = getMaxIncrement("iv");
            saveBase64File(initVector, "iv"+((ivIncrement==0)?"":ivIncrement)+".base64");
        }

        return new IvParameterSpec(initVector);
    }

    /**
     * Looks through the .base64 files in the directory with the matching prefix. Aims to find a pattern match and
     * use the number in the file to determine the next increment for a new .base64 file.
     * @param prefix - "key" or "iv" prefix to the
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

    /**
     * Creates a Base64 file by converting the given byte data. Data is saved to a file with the given filename.
     * @param data - Byte data that is to be converted to base64 and saved
     * @param filename - Name of file data is saved to
     */
    private static void saveBase64File(byte[] data, String filename) {
        try {Files.write(Paths.get("data/"+filename), Base64.getEncoder().encode(data));}
        catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to save data to "+filename);
            exit(1);
        }
        LOG.log(Level.INFO, "Successfully created base64 file. Saved to: " + filename);
    }

    /**
     * Takes and saves the command line args in a map using their more descriptive keywords.
     * @param args - Commandline arguments
     * @return Map of command line arguments
     */
    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> params = new HashMap<>();
        List<String> options = List.of("--input-file", "-i", "--output-file", "-o", "--mode", "-m", "--initialisation-vector", "-iv", "--key-file", "-k");
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

                if(key == null){
                    LOG.severe("Unrecognized argument: " + args[i]);
                    exit(1);
                }
                String value = args[i + 1];
                if(options.contains(value)){
                    LOG.severe("Two options provided with no values: \'" + key + "\', and \'" + value + "\'");
                    exit(1);
                }
                params.put(key, value);
            } else {
                LOG.severe("Argument " + args[i] + " is missing a value.");
                exit(1);
            }
        }
        return params;
    }

}