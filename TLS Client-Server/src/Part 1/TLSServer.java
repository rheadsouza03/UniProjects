import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class TLSServer {
    private static final int PORT = 8443;
    private static final String KEYSTORE_PATH = "server.jks";
    private static final String KEYSTORE_PASSWORD = "serverpassword";

    public static void main(String[] args) {
        try {
            // Load Server KeyStore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreInput = new FileInputStream(KEYSTORE_PATH)) {
                keyStore.load(keyStoreInput, KEYSTORE_PASSWORD.toCharArray());
            }

            // Initialize KeyManagerFactory with the server KeyStore
            KeyManagerFactory keyMngFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyMngFact.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS"); // Can be TLSv1.2/TLSv1.3, but match client
            sslContext.init(keyMngFact.getKeyManagers(), null, null);

            // Create SSLServerSocket
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            try (SSLServerSocket sslServer = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT)) {
                System.out.println("TLS server started. Waiting for client, listening on port " + PORT + "...");

                while (true) {
                    try (SSLSocket clientSocket = (SSLSocket) sslServer.accept()) {
                        System.out.println("Client connected: " + clientSocket.getInetAddress());

                        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

                        // Read message from client
                        String message = in.readLine();
                        System.out.println("Received from client: " + message);

                        // Send response to client
                        out.write("Hello, Client!\n");
                        out.flush();
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
