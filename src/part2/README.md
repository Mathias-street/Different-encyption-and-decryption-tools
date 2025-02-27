# How to use it!

You must state if you are encrypting or decrypting by "enc" or "dec", give a password, a plaintext file or encrypted file respectively and name the output file.

Example: Java part2.java enc -p helloworld -i plaintext.txt -o encrypted.enc

This command will encrypt the file plaintext.txt using the password helloworld and put the new encrypted plaintext into a file called encrypted.enc. 

Example: Java part2.java dec -p helloworld -i encrypted.enc -o decryptedText.dec

This command will change back the encrypted file into the plaintext. 


I do not need to provide the password salt in the command line because we save the salt to the 
ciphertext file. I read the file for the initialisation vector and the salt. which then I can derive
the key from the password and the salt. The salt is technically still being provided, but the user 
doesn't know that they are providing it.
