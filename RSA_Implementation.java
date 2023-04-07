package Assignment9;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;

class Keys{
    PublicKey pub;
    PrivateKey priv;

    public Keys(PublicKey p1, PrivateKey p2){
        this.pub=p1;
        this.priv=p2;
    }
    public PublicKey getPublicKey(){return this.pub;}
    public PrivateKey getPrivateKey(){return this.priv;}
}
public class RSA_Implementation {

    public static void main(String[] args) {
        Scanner sc=new Scanner(System.in);
        try {
            String input;
            if(args.length==0){
                System.out.println("You have to enter the message string to encrypt\nPlaintext message:");
                input=sc.nextLine();
            }
            else input =args[0];

            Assignment9.Keys keys = keyGeneration();

            System.out.println("Public Key generated - " + keys.getPublicKey());
            System.out.println("Private Key generated - " + keys.getPrivateKey());

            BigInteger[] rsaPairs = generatingKeyPairs(keys.getPublicKey(), keys.getPrivateKey());

            System.out.println("\n\nKey pairs generated are as follows - ");
            System.out.println("Public Key Modulus : " + rsaPairs[0]);
            System.out.println("Public Key Exponent : " + rsaPairs[1]);
            System.out.println("Private Key Modulus : " + rsaPairs[2]);
            System.out.println("Private Key Exponent : " + rsaPairs[3]);


            //Encryption using Public Key
            System.out.println("\n\n**** Encryption Process ****");
            System.out.println(" Before encryption, message = " + input);
            byte[] encryptedData = encryptPlaintext(input, keys.getPublicKey());
            System.out.println(" After encryption, ciphertext = " + encryptedData);


            //Decryption using Private Key
            System.out.println("\n\n**** Decryption Process ****");
            byte[] decrypted = decryptCiphertext(encryptedData, keys.getPrivateKey());
            System.out.println("Decrypted data = " + new String(decrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static BigInteger[] generatingKeyPairs(PublicKey publicKey, PrivateKey privateKey) {
        BigInteger[] b=new BigInteger[4];
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            b[0]=rsaPubKeySpec.getModulus();
            b[1]=rsaPubKeySpec.getPublicExponent();
            b[2]=rsaPrivKeySpec.getModulus();
            b[3]=rsaPrivKeySpec.getPrivateExponent();
        } catch (NoSuchAlgorithmException n){
            n.printStackTrace();
        }
        catch (InvalidKeySpecException i){
            i.printStackTrace();
        }
        return b;
    }

    private static Assignment9.Keys keyGeneration() {
        System.out.println("Generating Public and Private keys");
        PublicKey publicKey=null;
        PrivateKey privateKey=null;
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }catch (NoSuchAlgorithmException e){
            System.out.print("Exception!!"+e);
            e.printStackTrace();
        }
        Assignment9.Keys k =new Assignment9.Keys(publicKey,privateKey);
        return k;
    }

    public static byte[] encryptPlaintext(String input, PublicKey publicKey){
        byte[] encryptedData = null;
        try {
            byte[] plaintext = input.getBytes();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedData = cipher.doFinal(plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedData;
    }

    public static byte[] decryptCiphertext(byte[] data, PrivateKey privateKey){
        byte[] decrypt = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decrypt = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypt;
    }

}
