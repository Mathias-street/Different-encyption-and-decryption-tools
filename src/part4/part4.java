package part4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class part4 {
    private static int type = 1;
    private static final char[] LOWERCHARSET = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final char[] LOWERNUMBERCHARSET = "abcdefghijklmnopqrstuvwxyz1234567890".toCharArray();
    private static final char[] LOWERUPPERCHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final int MAX_LENGTH = 6;

    /**
     * Brute force attack on password type that is determined by user
     *
     * @param args
     */
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, IOException {
        // Get ciphertext
        //final Path path = Paths.get("/Users/mathiasmac/Documents/University/CYBR372/Assignment1/src/part4");
        // Get type of password to use

        if (args[1].equals("-t") || args[1].equals("--type")) {
            type = Integer.parseInt(args[2]);
        } else {
            throw new IllegalArgumentException("Type must be either '-t' or '--type' followed by either 0,1,2");
        }
        // Start with the first password e.g. all 'a' characters
        char[] combination = new char[MAX_LENGTH];
        if (type == 0) {
            Arrays.fill(combination, LOWERCHARSET[0]);
        } else if (type == 1) {
            Arrays.fill(combination, LOWERNUMBERCHARSET[0]);
        } else if (type == 2) {
            Arrays.fill(combination, LOWERUPPERCHARSET[0]);
        } else {
            throw new IllegalArgumentException("type must be 1 , 2 or 3");
        }

        //System.out.println("Initial combination: " + Arrays.toString(combination));

        // Plaintext
        String actualPlaintext = new String(Files.readAllBytes(Path.of(Path.of(args[0]).getParent() + "/" + "plaintext.txt")), StandardCharsets.UTF_8);

        long start = System.currentTimeMillis();

        while (true) {
            char[] password = generateNewPassword(combination);
            byte[] iv;
            byte[] salt;
            InputStream in = Files.newInputStream(Path.of(args[0]));
            // Read the IV and salt. If we didn't have these it would take an eternity
            DataInputStream dis = new DataInputStream(in);
            iv = new byte[16];
            dis.readFully(iv);
            salt = new byte[16];
            dis.readFully(salt);

            // Creating the initialization vector
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, 128);
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), "AES");

            System.out.println("Key: " + Base64.getEncoder().encodeToString(secretKeySpec.getEncoded()));
            System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));
            System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            String decryptedPlaintext = "";
            try {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                CipherInputStream decryptStream = new CipherInputStream(in, cipher);
                final byte[] bytes = new byte[1024];
                int length;
                while ((length = decryptStream.read(bytes)) != -1) {
                    buffer.write(bytes, 0, length);
                }
                decryptedPlaintext = new String(buffer.toString());
            } catch (IOException ex) {
                // Just to prevent console clutter with errors
                System.out.println();
            }

            // Check if newly decrypted text matches the plaintext
            if (decryptedPlaintext.equals(actualPlaintext)) {
                long end = System.currentTimeMillis();
                long elapsed = end - start;
                System.out.println("Password has been found!!");
                System.out.println("Password: " + new String(password));
                System.out.println("Elapsed time: " + elapsed + "ms");
                break;
            } else {
                long atm = System.currentTimeMillis();
                long elapsed = atm - start;
                System.out.println("Password has not been found yet!!");
                System.out.println("Password: " + new String(password));
                System.out.println("Elapsed time: " + elapsed + "ms");
            }
        }
    }

    /**
     * Generates new password to try
     * I had help with this method from chatgpt
     *
     * @param combination characters in the password
     * @return newly generated password
     */
    private static char[] generateNewPassword(char[] combination) {
        int length = combination.length;

        // Increment the combination array
        for (int i = length - 1; i >= 0; i--) {
            //when 'z' is reached go to 'A'
            int indexAscii = (int)combination[i];
            if (indexAscii > 122 && type == 2){
                combination[i] = 65;
            } else if (indexAscii == 122 && type == 1){
                combination[i] = 48;
            } else if (indexAscii == 57 && type == 1){
                combination[i] = 123;
            }
            //System.out.println(indexAscii);
            if (type == 0 && combination[i] < LOWERCHARSET[LOWERCHARSET.length - 1]) {
                combination[i]++;
                for (int j = i + 1; j < length; j++) {
                    combination[j] = LOWERCHARSET[0];
                }
                return combination;
            } else if (type == 1 && combination[i] < LOWERNUMBERCHARSET[25] || combination[i] < LOWERNUMBERCHARSET[LOWERNUMBERCHARSET.length-1]) {
                combination[i]++;
                for (int j = i + 1; j < length; j++) {
                    combination[j] = LOWERNUMBERCHARSET[0];
                }
                return combination;
            } else if (type == 2 && combination[i] > LOWERUPPERCHARSET[LOWERUPPERCHARSET.length - 1] && combination[i] < 123 || combination[i] < LOWERUPPERCHARSET[LOWERUPPERCHARSET.length - 1]) {
                combination[i]++;
                for (int j = i + 1; j < length; j++) {
                    combination[j] = LOWERUPPERCHARSET[0];
                }
                return combination;
            }
        }

        return null; // All combinations have been tried
    }


}
