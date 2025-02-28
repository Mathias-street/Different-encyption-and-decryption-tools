# How to use it!
You must have the corresponding plaintext for the encrypted text for this to work.

Use part 2 to encrypt a file using a maximum of six characters. 

Three different modes can be used in this: 
- '0' is for passwords with **ONLY lowercase** characters
- '1' is for passwords with **lowercase** and **numbers** characters
- '2' is for passwords with **lowercase** and **uppercase** characters

The encrypted file to be brute-forced **MUST** be first argument in the command line

Example: Java part4.java encryptedtext.enc -t 0

This will go through every single six charater password possible starting from aaaaaa to zzzzzz

Same usage is for the other mores just type 1 or 2 instead of 0. 

# Discussion
Brute forcing password with only lower case possibilities that is 6 characters long.

Password used: "trucks" 

I stopped the bruteforce after about a minute which it had reached up to "abbebb". With only 
lowercase letters and 6 characters long, there are 308,915,776 (26^6) different combinations. "abbebb"
is only 0.15% the way through the entire combinations and with the comination number of 477,283.
Its about 0.20% away from "trucks" which means it has about 29,339 minutes to go.
(Time for "trucks"=60×(233,390,603/477,283))


Brute forcing password with lowercase and numbers

Password used: "7ruc1s"

Once 60 seconds had been reached I stopped the brute force and it had reached the combination
"aalfn6". With lowercase letters and numbers the total number of combinations are 2,176,782,336. 
This will take another 64 hours around about until we reach the password "7ruc1s". We are doing 8886 combinations
per second and there are 2,042,172,571 left till that password. (2,042,172,571/8886)/3600 = 64 hours.


Brute forcing password with lowercase and uppercase letters.

Password used: "TrUcKs"

After about 60 seconds we reached the combination "aadDOZ". there are 19,770,609,664 combinations.
This will take around 79 hours to reach the password "TrUcKs". With the same working as above.


So we can see having a mix of different characters and numbers can have a huge difference on 
how long it could take an attack to break into someone's account if they already knew their username.

