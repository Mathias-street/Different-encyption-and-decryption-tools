package part2;

import javax.crypto.*;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.PBEKeySpec;



public class part2 {
    private static final Logger LOG = Logger.getLogger(part2.class.getSimpleName());

    private static final String ALGORITHM = "AES";

    //fields for the parameters to live in.
    private static boolean encrypt = true;
    private static String mode = "AES/CBC/PKCS5PADDING";
    private static String inputFile = "";
    private static String outputFile = "";
    private static char[] password;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        //check if first argument is stating whether it is encrypting or decrypting,
        //if not stated throw an exception.
        if (args[0].equals("enc")) {
            encrypt = true;
        } else if (args[0].equals("dec")) {
            encrypt = false;
        } else {
            throw new IllegalArgumentException("Must state 'enc' for encrypt or 'dec' to decrypt as first argument");
        }

        //now go through the rest of the arguments given by the user and set each one accordingly.
        for (int i = 1; i < args.length; i++) {
            String parameter = args[i];
            if (parameter.equals("-p") || parameter.equals("--pass")) {
                i++;
                password = args[i].toCharArray();
            } else if (parameter.equals("-i") || parameter.equals("--input-file")) {
                i++;
                inputFile = args[i];
            } else if (parameter.equals("-o") || parameter.equals("--output-file")) {
                i++;
                outputFile = args[i];
            }
        }
        //iv and salt are randomly generated
        byte[] iv = new byte[16];
        byte[] salt = new byte[16];
        SecretKeySpec secretKeySpec;

        //Look for files here
        //have edited it slightly to just either encrypt or decrypt not do both.
        //copied out of https://github.com/PacktPublishing/Hands-On-Cryptography-with-Java/blob/master/src/main/java/com/packtpub/crypto/section5/FileEncryptor.java
        if (encrypt) {
            try (InputStream fin = Files.newInputStream(Path.of(inputFile));
                 FileOutputStream fout = new FileOutputStream(outputFile)) {

                SecureRandom sr = new SecureRandom();
                sr.nextBytes(salt);
                sr.nextBytes(iv);

                PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, 128);
                SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
                secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

                System.out.println("Key: " + Base64.getEncoder().encodeToString(secretKeySpec.getEncoded()));
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));
                System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));
                Cipher cipher = Cipher.getInstance(mode);

                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                // Write IV and salt before encryption
                fout.write(iv);
                fout.write(salt);

                try (CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {
                    byte[] bytes = new byte[1024];
                    int length;
                    while ((length = fin.read(bytes)) != -1) {
                        cipherOut.write(bytes, 0, length);
                    }
                    cipherOut.flush();
                }

            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }

            LOG.info("Encryption finished, saved at " + Path.of(outputFile));
        } else {
            final Path decryptedPath = Path.of(outputFile);
            try (OutputStream fout = Files.newOutputStream(decryptedPath);
                 InputStream fin = Files.newInputStream(Path.of(inputFile))){

                DataInputStream dis = new DataInputStream(fin);
                dis.readFully(iv);
                dis.readFully(salt);

                PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, 128);
                SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
                secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));
                System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));
                Cipher cipher = Cipher.getInstance(mode);

                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                System.out.println("Key: " + Base64.getEncoder().encodeToString(secretKeySpec.getEncoded()));

                try (CipherInputStream cipherIn = new CipherInputStream(fin, cipher)) {
                    byte[] bytes = new byte[1024];
                    int length;
                    while ((length = cipherIn.read(bytes)) != -1) {
                        fout.write(bytes, 0, length);
                    }
                    fout.flush();
                }

            } catch (IOException ex) {
                Logger.getLogger(part2.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

            LOG.info("Decryption complete, open " + decryptedPath);
        }

    }
}
