package org.example.md5;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Md5 {
    public static String getMd5(String input) {
        try {
            //getInstance() method is called with algorithm SHA-1
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());

            //Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            //Convert message digest into hex value
            String hashText = no.toString(16);

            //Add preceding 0s to make it 32 bit
            while (hashText.length() < 32) {
                hashText = "0" + hashText;
            }

            return hashText;
        }

        //For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }
}
