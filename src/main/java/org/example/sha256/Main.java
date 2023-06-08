package org.example.sha256;

import java.security.NoSuchAlgorithmException;

import static org.example.sha256.Sha256.getSHA;
import static org.example.sha256.Sha256.toHexString;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("HashCode Generated by SHA-256 for: ");

            String str1 = "ADA University";
            System.out.println("\n" + str1 + ": " + toHexString(getSHA(str1)));

            String str2 = "Div Academy";
            System.out.println("\n" + str2 + ": " + toHexString(getSHA(str2)));

            String str3 = "Illinois University";
            System.out.println("\n" + str3 + ": " + toHexString(getSHA(str3)));
        }

        //For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e);
        }
    }
}