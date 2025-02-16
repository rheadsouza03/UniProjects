# Description:
This is a command-line encryption/decryption program. Must be compiled and run using command-line arguments.

## Command structure:
Compile using: `javac Part1`. 
Command-line argument: `java Part1 ` <`enc`||`dec`>  `[OPTIONS]`
Note: 'enc' and 'dec' are not case-sensitive

### `[OPTIONS]`:
 - `-k` && `--key-file`: followed by a `".base64"` file is to be provided with this option. Mandatory for decryption. 
    Can be randomly generated if not specified for encryption.
 - `-iv` && `--initialisation-vector`: followed by a `".base64"` file is to be provided with this option. Mandatory for decryption. 
    Can be randomly generated if not specified for encryption.
 - `-m` && `--mode`: followed by the AES mode. Available options are 'ECB/CBC/CTR/OFB/CFB/GCM'. 
    Defaults to 'AES/CBC/PKCS5PADDING' if not provided.
 - `-i` && `--input-file`: mandatory parameter. For encryption = plaintext, decryption = ciphertext (i.e. encrypted data).
 - `-o` && `--output-file`: optional parameter. For encryption = ciphertext (will end with `".enc"` if not already), 
    decryption = decrypted data (will end with `".dec"` if not already).

References: Mainly javadocs and StackOverflow. Additionally, the original encryption code was utilised to understand 
the structure of performing the initialisation and encryption/decryption parts.
