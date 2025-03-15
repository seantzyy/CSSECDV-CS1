/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package Controller;

import java.security.NoSuchAlgorithmException;  
import java.security.SecureRandom;  
import java.security.spec.InvalidKeySpecException;  
import java.util.Arrays;  
import java.io.InputStream;
import java.util.Base64;  
import java.util.Random;  
import javax.crypto.SecretKeyFactory;  
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.spec.PBEKeySpec;
import java.util.Properties;

/**
 *
 * @author cochi
 */
/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

public class Hashing {
    /* Declaration of variables */   
    private static final Random random = new SecureRandom();  
    private static final String chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";  
    private static final int iterate = 10000;  
    private static final int keysize = 256;  
    private static String salt = init();
     
    private static String init(){
        try (InputStream input = new FileInputStream("config.properties")) {

            Properties prop = new Properties();

            prop.load(input);

            return prop.getProperty("SALT");

        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    /* Generate the salt value. */
    public static String getSaltvalue(int length) {
        StringBuilder finalval = new StringBuilder(length);
  
        for (int i = 0; i < length; i++) {
             finalval.append(chars.charAt(random.nextInt(chars.length())));
        }
  
         return new String(finalval);
    }
  
    /* Generate the hash value */
    public static byte[] hash(char[] password, byte[] salt) {
         PBEKeySpec spec = new PBEKeySpec(password, salt, iterate, keysize);
             try {
                 SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
             return skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
            } finally {
            spec.clearPassword();
        }
    }
  
    /* Encrypt the password using the original password and salt value. */
    public static String generateSecurePassword(String password) {
         String finalval = null;

        byte[] securePassword = hash(password.toCharArray(), Hashing.salt.getBytes());

        finalval = Base64.getEncoder().encodeToString(securePassword);

        return finalval;
    }       
    
      
    /* Verify if both password are a match or not */  
    public static boolean verifyUserPassword(String providedPassword,  
            String securedPassword)  
    {  
        boolean finalval = false;  
          
        /* Generate New secure password with the same salt */  
        String newSecurePassword = generateSecurePassword(providedPassword);  
          
        /* Check if two passwords are equal */  
        finalval = newSecurePassword.equalsIgnoreCase(securedPassword);  
          
        return finalval;  
    }  
}

