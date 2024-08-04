# AES-PX-CBC
This repository contains the implementation of AES-PX-CBC.

AES-PX-CBC (AES Plain XOR Cipher Block Chaining) enhances the block dependency beyond what is achieved with standard CBC. Unlike traditional CBC, which uses XOR of the previous ciphertext block with the current plaintext block, AES-PX-CBC uses XOR of the previous plaintext block with the current plaintext block before applying AES encryption.

While this approach does not increase the entropy of the encrypted data, it significantly strengthens the interdependency between blocks, making it more resistant to certain types of cryptographic attacks. This enhanced block dependency provides an additional layer of security, particularly in environments where memory may be compromised.