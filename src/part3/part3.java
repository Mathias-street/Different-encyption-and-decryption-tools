package part3;


import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
//code from part1
public class part3 {
    private static final Logger LOG = Logger.getLogger(part3.class.getSimpleName());

    private static final String ALGORITHM = "AES";

    //fields for the parameters to live in.
    private static boolean encrypt = true;
    private static String keyFilePath = "";
    private static String initialisationVectorPath = "";
    private static String mode = "AES/CBC/PKCS5PADDING";
    private static String inputFile = "";
    private static String outputFile = "";
    private static int keyLength = 256;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        //check if first argument is stating whether it is encrypting or decrypting,
        //if not stated throw an exception.
        if (args[0].equals("enc")){
            encrypt = true;
        } else if (args[0].equals("dec")){
            encrypt = false;
        } else {
            throw new RuntimeException("Must state 'enc' for encrypt or 'dec' to decrypt as first argument");
        }

        //now go through the rest of the arguments given by the user and set each one accordingly.
        for (int i = 1; i < args.length ; i++){
            String parameter = args[i];
            if (parameter.equals("-k") || parameter.equals("--key-file")){
                i++;
                keyFilePath = args[i];
            } else if (parameter.equals("-iv") || parameter.equals("--initialisation-vector")){
                i++;
                initialisationVectorPath = args[i];
            } else if (parameter.equals("-m") || parameter.equals("--mode")){
                i++;
                mode = "AES/" + args[i] + "/PKCS5PADDING";
            } else if (parameter.equals("-i") || parameter.equals("--input-file")){
                i++;
                inputFile = args[i];
            } else if (parameter.equals("-o") || parameter.equals("--output-file")){
                i++;
                outputFile = args[i];
            }
        }

        //This snippet is literally copied from SymmetrixExample
        byte[] key = new byte[keyLength/8];
        byte[] initVector = new byte[16];

        if (encrypt){
            SecureRandom sr = new SecureRandom();
            // if the key path is empty make a new random key to use for the encryption
            if (keyFilePath.isEmpty()) {
                sr.nextBytes(key);

                // writing key to a file called key.base64 in the same file as the input
                FileWriter fw = new FileWriter(Path.of(inputFile) + "/" + "key.base64");
                fw.write(Base64.getEncoder().encodeToString(key));
                fw.close();

                System.out.println("Random key=" + key.toString());
            } else {
                key = readFile(keyFilePath,"key");
                System.out.println("key from file =" + key.toString());
            }
            // if the init vector path is empty make a new random init vector to use for the encryption
            if (initialisationVectorPath.isEmpty()){
                sr.nextBytes(initVector); // 16 bytes IV
                FileWriter fw = new FileWriter(Path.of(inputFile).getParent() + "/" + "iv.base64");
                fw.write(Base64.getEncoder().encodeToString(initVector));
                fw.close();

                System.out.println("initVector=" + initVector.toString());
            } else {
                initVector = readFile(initialisationVectorPath,"iv");
                System.out.println("initVector from file =" + initVector.toString());
            }

        } else {
            // reading the key file
            if (keyFilePath.isEmpty()){
                throw new RuntimeException("Key file must be specified");
            }

            if (initialisationVectorPath.isEmpty()){
                throw new RuntimeException("Initialization vector must be specified");
            }

            key = readFile(keyFilePath,"key");
            initVector = readFile(initialisationVectorPath,"iv");

            System.out.println("key from file =" + key.toString());
            System.out.println("initVector from file =" + initVector.toString());
        }
        //Checks for encryption and decryption input files
        if (encrypt && inputFile.isEmpty()){
            throw new RuntimeException("Must have an input file (plaintext file) if you choose to use encryption function");
        } else if (encrypt && !inputFile.contains(".txt")){
            throw new RuntimeException("Input file must contain txt file (.txt extension)");
        } else if (!encrypt && inputFile.isEmpty()){
            throw new RuntimeException("Must have an input file (ciphertext) if you choose to use decryption function");
        } else if (!encrypt && !inputFile.contains(".enc")){
            throw new RuntimeException("Input file must contain encrypted file (.enc extension)");
        }
        //Checks for the output file extension
        if (!outputFile.isEmpty()) {
            if (encrypt && !outputFile.contains(".enc")) {
                throw new RuntimeException("Output file must contain encrypted file (.enc extension) if you choose to use encryption function");
            } else if (!encrypt && !outputFile.contains(".txt")) {
                throw new RuntimeException("Output file must contain txt file (.txt extension) if you choose to use decryption function");
            }
        }
        //if output file isnt given, then name the output file the same as the input file and add the correct extension
        if (outputFile.isEmpty()){
            if (encrypt){
                outputFile = inputFile + ".enc";
            } else {
                outputFile = inputFile + ".dec";
            }
        }

        IvParameterSpec iv;
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher;

        //depending on mode chosen to use different padding and IV need to be used to work with getInstance() method
        switch (mode){
            case "ECB":
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec);
                }
                break;
            case "CBC":
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                iv = new IvParameterSpec(initVector);
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                }
                break;
            case "CTR":
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                iv = new IvParameterSpec(initVector);
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                }
                break;
            case "OFB":
                cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
                iv = new IvParameterSpec(initVector);
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                }
                break;
            case "CFB":
                cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
                iv = new IvParameterSpec(initVector);
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec , iv);
                }
                break;
            case "GCM":
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new GCMParameterSpec(keyLength, initVector));
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec, new GCMParameterSpec(keyLength, initVector));
                }
                break;
            default:
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                iv = new IvParameterSpec(initVector);
                if(encrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                }
                break;
        }

        //Look for files here
        //have edited it slightly to just either encrypt or decrypt not do both.
        //final Path path = Paths.get("/Users/mathiasmac/Documents/University/CYBR372/Assignment1/src/part3");
        Path encryptedPath = Paths.get(inputFile);
        //total time to encrypt or decrypt
        double total = 0;
        if (encrypt) {
            encryptedPath = Paths.get(outputFile);
            try (InputStream fin = Files.newInputStream(Path.of(inputFile));
                 OutputStream fout = Files.newOutputStream(encryptedPath)) {
                final byte[] data = fin.readAllBytes();

                //time the encryption process
                long start = System.nanoTime();
                byte[] encyptedData = cipher.doFinal(data);
                long end = System.nanoTime();
                //convert back to milliseconds
                total = (end - start) / 1_000_000.0;

                fout.write(encyptedData);
                System.out.println("Total encryption time with key length " + (keyLength) + " bits" + " with mode "
                        + mode + " in " + total + " ms");
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new RuntimeException(e);
            }

            LOG.info("Encryption finished, saved at " + encryptedPath);
        } else {
            final Path decryptedPath = Paths.get(outputFile + ".dec");
            try (InputStream fin = Files.newInputStream(encryptedPath);
                 OutputStream fout = Files.newOutputStream(decryptedPath)) {
                final byte[] data = fin.readAllBytes();
                //time the decryption process
                long start = System.nanoTime();
                byte[] decryptedData = cipher.doFinal(data);
                long end = System.nanoTime();
                total = (end - start) / 1_000_000.0;

                fout.write(decryptedData);

                System.out.println("Total decryption time with key length " + (keyLength) + " bits" + " with mode " + mode + " in " + total + " ms");
            } catch (IOException ex) {
                Logger.getLogger(part3.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new RuntimeException(e);
            }

            LOG.info("Decryption complete, open " + decryptedPath);
        }
        appendFile(total);
    }

    //method to read either key or init vector file
    public static byte[] readFile(String filepath, String keyOrIv) throws IOException {

        BufferedReader br = new BufferedReader(new FileReader(filepath));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        //making a copy so i can make sure the key is always 16 bytes long
        byte[] copy = Base64.getDecoder().decode(sb.toString());
        //getting ready to read initial vector file
        br.close();
        sb.setLength(0);

        if (keyOrIv.equals("key")) {
            return Arrays.copyOf(copy, keyLength / 8);
        } else if (keyOrIv.equals("iv")) {
            return Arrays.copyOf(copy, 16);
        } else {
            throw new IOException("Unsupported key or iv");
        }
    }
    //append results to results.csv
    public static void appendFile(double time) throws IOException {
        FileWriter csv = new FileWriter("/Users/mathiasmac/Documents/University/CYBR372/Assignment1/src/part3/results.csv" ,true);
        String eOrd;
        if (encrypt){
            eOrd = "encryption";
        } else {
            eOrd = "decryption";
        }
        csv.write("\n");
        csv.write(inputFile + "," + mode + "," + keyLength + "," + eOrd + "," + time + "ms,");
        csv.close();
        System.out.println("Appended results of " + eOrd + " to results.csv file");
    }
}
