# Part 1
## Generating, Signing and Creating the TrustedCA using a root and server private key and certificate
Run commands in order
1. `keytool -genkeypair -alias rootca -keyalg RSA -keysize 2048 -dname "CN=RootCA, OU=IT, O=None, L=Wellington, S=None, C=NZ" -keypass capassword -keystore rootca.jks -storepass capassword -validity 1`
2. `keytool -exportcert -alias rootca -keystore rootca.jks -storepass capassword -file rootca.crt`
3. `keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -dname "CN=localhost, OU=IT, O=None, L=Wellington, S=None, C=NZ" -keypass serverpassword -keystore server.jks -storepass serverpassword -validity 1`
4. `keytool -certreq -alias server -keystore server.jks -storepass serverpassword -file server.csr`
5. `keytool -gencert -alias rootca -keystore rootca.jks -storepass capassword -infile server.csr -outfile server.crt -validity 365 -ext "SAN=DNS:localhost"`
6. `keytool -importcert -alias rootca -file rootca.crt -keystore server.jks -storepass serverpassword -noprompt`
7. `keytool -importcert -alias server -file server.crt -keystore server.jks -storepass serverpassword`
8. `keytool -importcert -alias rootca -file rootca.crt -keystore clienttruststore.jks -storepass trustpassword -noprompt`



### Sources used for client-server implementation
- https://www.geeksforgeeks.org/how-to-secure-communication-using-ssl-tls-in-java/