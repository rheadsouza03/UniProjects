import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;

public class TLSClient {
    private static String host = "localhost";
    private static final int PORT = 443; // Ensure this matches the server's port (HTTPS)
    private static  String truststorePath = "rootca.jks";
    private static String truststorePassword = "capassword";

    public static void main(String[] args) {
        try {
            // Load the CA certificate into the truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (FileInputStream trustStoreInput = new FileInputStream(truststorePath)) {
                trustStore.load(trustStoreInput, truststorePassword.toCharArray());
            }

            // Initialize TrustManagerFactory
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

            // Create SSLSocket
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            try (SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, PORT);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(sslSocket.getOutputStream(), true)) {

                // Send a message to the server
                writer.println("Hello, Server!");

                // Read the response
                String response = reader.readLine();
                System.out.println("Received: " + response);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
