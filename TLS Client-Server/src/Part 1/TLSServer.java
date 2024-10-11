import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.security.KeyStore;

public class TLSServer {
    private static final int PORT = 8443; // non-previledged port
    private static String keystorePath = "server.jks";
    private static String keystorePassword = "serverpassword";

    public static void main(String[] args) {
        try {
            // Load the server's private keystore and certificate
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreInput = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInput, keystorePassword.toCharArray());
            }

            // Initialize KeyManagerFactory
            KeyManagerFactory keyMngFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyMngFact.init(keyStore, keystorePassword.toCharArray());

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyMngFact.getKeyManagers(), null, new java.security.SecureRandom());

            // Create SSLServerSocket
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            try (SSLServerSocket sslServer = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT)) {
                System.out.println("TLS server started. Waiting for client, listening on port " + PORT + "...");

                while(true) {
                    try (SSLSocket sslSocket = (SSLSocket) sslServer.accept();
                         BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                         PrintWriter writer = new PrintWriter(sslSocket.getOutputStream(), true)) {

                        System.out.println("Client connected");

                        // Read message from client
                        String message = reader.readLine();
                        System.out.println("Received: " + message);

                        // Send response
                        writer.println("Hello, Client!");
                    } catch (IOException e) {
                        System.err.println("Connection error: " + e.getMessage());
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
