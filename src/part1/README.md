## How to use!
first you must have a plaintext file you wish to encrypt.
in the command line type: Java part1.java enc -i [plaintext file goes here]  DO NOT INCLUDE BRACKETS

That part is needed to make the encryption work. Optionally you can add other options to it to do specific things if needed.
If you have a key you want to use (must me 16 bytes), you can type: -k [key name goes here]. if you have an initialisation
vector you want to use you can do the same as the key but type: -iv [iv name goes here]. Another argument you can pass is
-m which ill allow you to choose a specific mode. example Type: -m [pick one of these modes: ECB, CBC, CTR, OFB, CFB or GCM]. The
default mode is CBC if you decide to not specify one. you can also choose an output file to put the encrypted message into.
it MUST contain .enc at the end of the name. example Type: -o encryptedFile.enc 

if just chosen to only have the input file, everything will be made for you [i.e the key and iv will be generated randomly].

an example is: java part1.java enc -i plaintext.txt -k key.base64 -iv iv.base64 -m GCM -o secret.enc  

Now to decrypt this is mandatory: java part1.java dec -i [encrypted file goes here] -iv [initialisation vector file goes here]
-k [key file goes here]. 

if you have used a mode you MUST state the mode, therefore add onto the command line: -m [mode you used to encrypt the file].
you can also state an output file you can add -o [name of output file].txt, THIS MUST HAVE .txt extension otherwise wont work. 

