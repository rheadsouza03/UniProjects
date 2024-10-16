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
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.System.exit;

/**
 * Tests different keys, input file sizes and cipher modes and appends their timings into the results.csv file.
 * @author Rhea D'Souza
 * UID: dsouzrhea
 */
public class Part3 {
    private static final Logger LOG = Logger.getLogger(Part3.class.getSimpleName());

    private static final String ALGORITHM = "AES";

    private static final String[] CIPHERS = {
            "AES/CBC/PKCS5Padding",
            "AES/ECB/PKCS5Padding",
            "AES/OFB/NoPadding",
            "AES/CFB/NoPadding",
            "AES/CTR/NoPadding",
            "AES/GCM/NoPadding"
    };
    private static final int[] KEY_SIZES = {128, 192, 256}; // in bits
    private static File[] INPUT_FILES = new File[3];
    private static final int[] INPUT_FILES_SIZES = {128, 256, 512};
    private static final int ITERATIONS = 100;

    /**
     * Loops through temporarily created input plaintext files, key sizes, and operation modes for encryption
     * and decryption. The initialises these variable and gets the duration of the 2 operations by performing
     * encryption and decryption and storing the results in a map. This map is then used to add the relevant
     * information gained from this testing, to the 'results.csv' file.
     * @param args - commandline arguments
     */
    public static void main(String[] args){
        // Creates temporary plaintexts and ensures they get deleted upon JVM shutdown of the program.
        createTempPlaintexts();
        Runtime.getRuntime().addShutdownHook(new Thread(Part3::deleteTempPlaintexts));

        // Initialising duration encryption and decryption HashMaps
        Map<int[], Double> encryptionDurations = new HashMap<>();
        Map<int[], Double> decryptionDurations = new HashMap<>();

        for(int i = 0; i < INPUT_FILES.length; i++){ // Loops through input files
            for(int j = 0; j < KEY_SIZES.length; j++){ // Loops through key sizes
                for(int k = 0; k < CIPHERS.length; k++){ // Loops through cipher modes
                    SecureRandom sr = new SecureRandom();

                    // Create random key
                    byte[] key = new byte[(int)(KEY_SIZES[j] / 8)]; // Default key size
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

                    // Perform multiple iterations of encryption and decryption and collect their durations
                    double[] iterDurations = getAverageDurations(skeySpec, INPUT_FILES[i], cipher, sr);

                    // Store collected durations
                    encryptionDurations.put(new int[]{i, j, k}, iterDurations[0]);
                    decryptionDurations.put(new int[]{i, j, k}, iterDurations[1]);
                }
            }
        }
        LOG.info("All average durations have been calculated, successfully. " +
                         "\nSaving encryption information to 'result.csv' has started...");

        performSavePerformDur("Encryption", encryptionDurations);
        LOG.info("Encryption durations have successfully been saved. \nSaving decryption information to 'result.csv'....");
        performSavePerformDur("Decryption", decryptionDurations);
        LOG.info("Decryption durations have successfully been saved. \nThe result.csv is ready for viewing.");

    }

    /**
     * Gets the average duration taken to perform encryption and decryption with the given values.
     * @param inputFile - String with the input file name
     * @return Double array with encryption average stored at index 0 and decryption stored in index 1
     */
    private static double[] getAverageDurations(SecretKeySpec skeySpec, File inputFile, String cipherMode, SecureRandom sr) {
        double[] durations = {0, 0};

        for (int i = 0; i < ITERATIONS; i++) {
            // Generate a new IV for each iteration if using GCM mode
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector);
            IvParameterSpec iv = new IvParameterSpec(initVector);

            // Get pre-initialised Cipher instance
            Cipher cipherEnc = getCipher(cipherMode, Cipher.ENCRYPT_MODE, skeySpec, iv);
            Cipher cipherDec = getCipher(cipherMode, Cipher.DECRYPT_MODE, skeySpec, iv);

            // Perform encryption and decryption, and get the summation of their durations
            double[] encAndDecDur = performOperation(cipherEnc, cipherDec, inputFile);
            durations[0] += encAndDecDur[0];
            durations[1] += encAndDecDur[1];
        }

        durations[0] /= ITERATIONS;
        durations[1] /= ITERATIONS;
        LOG.info("Average durations for " + inputFile + " with cipher " + cipherMode + " have been computed.");

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
            byte[] initVector = iv.getIV();
            if (cipherMode.equals("AES/GCM/NoPadding")) {
                cipher.init(operation, skeySpec, new GCMParameterSpec(128, initVector));
            }
            else if (cipherMode.equals("AES/ECB/PKCS5Padding")){cipher.init(operation, skeySpec);}
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
     * @param cipherEnc - Cipher instance used to perform encryption
     * @param cipherDec - Cipher instance used to perform decryption
     * @param inputFile - file containing the encrypted/ciphertext data
     * @return Double array containing the duration for encryption and decryption operations to take place.
     */
    private static double[] performOperation(Cipher cipherEnc, Cipher cipherDec, File inputFile){
        double[] durations = {0,0};
        try {
            // Gets the file path
            Path inputPath = inputFile.toPath();

            // Performs encryption and measures duration
            double start = System.nanoTime();
            byte[] ciphertext = cipherEnc.doFinal(Files.readAllBytes(inputPath));
            double end = System.nanoTime();
            durations[0] = (end - start);

            // Performs decryption and measures duration
            start = System.nanoTime();
            cipherDec.doFinal(ciphertext);
            end = System.nanoTime();
            durations[1] = (end - start);

            return durations;
        } catch (IllegalBlockSizeException e) {
            LOG.severe("Unable to perform operation: Illegal block size. Cannot perform encryption.");
            exit(1);
        } catch (BadPaddingException e) {
            LOG.severe("Unable to perform operation: Bad padding. Cannot perform encryption.");
            exit(1);
        }catch (IOException e) {
            LOG.severe("Unable to perform operation: Error occurred when reading or writing to a file.");
            exit(1);
        }

        return null;
    }

    /**
     * Creates temporary plaintext files for the duration of this program.
     */
    private static void createTempPlaintexts() {
        if (INPUT_FILES[0] != null) {return;}
        LOG.info("Creating temporary plaintext files...");

        SecureRandom sr = new SecureRandom();
        try {
            for (int i = 0; i < INPUT_FILES.length; i++) {
                // Create a temporary file
                INPUT_FILES[i] = File.createTempFile(
                        "plaintext" + (i + 1),
                        ".txt",
                        new File(".")
                );

                // Determine the size of the file
                int fileSize = INPUT_FILES_SIZES[i]/8; // Convert bits to bytes

                // Create a byte array of the desired size
                byte[] data = new byte[fileSize];
                sr.nextBytes(data); // Fill with random data

                // Write the data to the file
                try (FileOutputStream fos = new FileOutputStream(INPUT_FILES[i])) {fos.write(data);}
            }
            LOG.info("Plaintext files have been created and populated successfully.");
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Error creating or writing to temporary files.");
            exit(1);
        }
    }

    /**
     * Delete the temporary plaintext.txt files.
     */
    private static void deleteTempPlaintexts() {
        for (File file : INPUT_FILES) {
            if (file != null && file.exists() && !file.delete()) {
                LOG.warning("Failed to delete temporary file: " + file.getAbsolutePath());
            }
        }
    }

    /**
     * Iterates over the map entries and calls savePerformanceMetrics to save the results to results.csv
     * @param operation - encryption or decryption operation
     * @param operationDurations - map of changing factors linked to its respective output duration for the given operation
     */
    private static void performSavePerformDur(String operation, Map<int[], Double> operationDurations) {
        // Sorts the durations in the map using the int array key
        List<Map.Entry<int[], Double>> sortedEntries = new ArrayList<>(operationDurations.entrySet());
        sortedEntries.sort((e1, e2) -> {
            int[] id1 = e1.getKey();
            int[] id2 = e2.getKey();
            // First, compare by file size
            int result = Integer.compare(INPUT_FILES_SIZES[id1[0]], INPUT_FILES_SIZES[id2[0]]);
            if (result != 0) return result;
            // Next, compare by key size
            result = Integer.compare(KEY_SIZES[id1[1]], KEY_SIZES[id2[1]]);
            if (result != 0) return result;
            // Finally, compare by mode
            return CIPHERS[id1[2]].compareTo(CIPHERS[id2[2]]);
        });

        // Write the header to the csv file
        String header = String.format("%s:\nFileSize(bits),KeySize(bits),Mode,Duration(secs)\n", operation);
        writeToCSV(header.getBytes());

        for(Map.Entry<int[], Double> entry : sortedEntries){
            int[] id = entry.getKey();
            // Format data for csv
            String performanceMetric = String.format(
                    "%d,%d,%s,%.2f\n",
                    INPUT_FILES_SIZES[id[0]],
                    KEY_SIZES[id[1]],
                    CIPHERS[id[2]].substring(4, 7),
                    (entry.getValue()/1000)
            );
            writeToCSV(performanceMetric.getBytes());
        }
        LOG.info("Performed save operation: "+operation);
    }

    /**
     * Writes the given data entry into the 'results.csv file'
     * @param entry - byte array of data to write to the csv file.
     */
    private static void writeToCSV(byte[] entry){
        try {
            Files.write(Paths.get("results.csv"), entry, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Unable to save entry to CSV.");
            exit(1);
        }
    }

}