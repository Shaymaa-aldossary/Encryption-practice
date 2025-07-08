
# Hybrid File Encryption Project (AES + RSA)

This project demonstrates how to securely encrypt and decrypt files using a hybrid cryptographic system that combines *AES* (symmetric encryption) and *RSA* (asymmetric encryption), written in Python.

##  Folder Structure
-  keys/
         Stores the RSA key pair:
             - private_key.pem: The encrypted private key, protected with a user-entered password
             - public_key.pem: The public key used to encrypt the AES key
-  encrypted/
         Contains all encrypted outputs:
             - aes_key.enc: The AES key encrypted using RSA
             - iv.bin: The initialization vector (IV) used with AES
             - fake_data.enc: Encrypted version of the JSON test file
             - fake_message.enc: Encrypted version of the TXT test file
-  decrypted/
         Holds the decrypted versions of the test files:
             - fake_data.json: Decrypted JSON file
             - fake_message.txt: Decrypted
-  test_data/
         Includes raw input files used for testing encryption:
             - fake_data.json
             - fake_message.txt
-  Main Program File:
          main.py: The full hybrid encryption script, from key generation to encryption and decryption


##  Features

-  RSA key pair generation
-  AES key encryption with RSA
-  Secure password input (via `getpass`)
-  Password validation (length, symbol, etc.)
-  Auto folder creation to avoid path errors
-  Separation of encrypted/decrypted files for clarity

## What’s New in updated_version ?
 - Replaced hardcoded password with dynamic input using getpass() for better security.
- Added password strength validation (minimum length and required special character).
- Automatically creates required folders (keys/, encrypted/, decrypted/, etc.) to avoid runtime errors.
- Saves the private RSA key securely encrypted using the user-provided password.
- Organized all files into clearly separated folders for better readability and project structure.
- Included helpful user messages at each step to improve usability and clarity.
- Streamlined code layout for easier maintenance and future scalability.




