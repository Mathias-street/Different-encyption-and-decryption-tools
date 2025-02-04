I do not need to provide the password salt in the command line because we save the salt to the 
ciphertext file. I read the file for the initialisation vector and the salt. which then I can derive
the key from the password and the salt. The salt is technically still being provided but the user 
doesn't know that they really are providing it.