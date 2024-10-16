import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class TLSClient {
    private static final String HOST = "localhost";
    private static final int PORT = 8443;
    private static final String TRUSTSTORE = "clienttruststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "trustpassword";

    public static void main(String[] args) {
        try {
            // Load Client TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (FileInputStream trustStoreIS = new FileInputStream(TRUSTSTORE)) {
                trustStore.load(trustStoreIS, TRUSTSTORE_PASSWORD.toCharArray());
            }
            // Initialize TrustManagerFactory with the TrustStore
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(trustStore);

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS"); // Can be TLSv1.2/TLSv1.3, but match server
            sslContext.init(null, tmf.getTrustManagers(), null);

            // Create SSLSocket
            SSLSocketFactory ssf = sslContext.getSocketFactory();
            try (SSLSocket sslSocket = (SSLSocket) ssf.createSocket(HOST, PORT)) {
                sslSocket.startHandshake();
                System.out.println("TLS Handshake completed successfully.");

                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
                BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));

                // Send message to server
                out.write("Hello, Server!\n");
                out.flush();
                System.out.println("Sent to server: Hello, Server!");

                // Read response from server
                String response = in.readLine();
                System.out.println("Received from server: " + response);
            } catch (SSLHandshakeException e) {
                System.err.println("SSL Handshake failed: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
