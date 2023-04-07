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

    public static void main(String[] args) throws IOException {

        Scanner sc=new Scanner(System.in);
        try {
            String input;
            if(args.length==0){
                System.out.println("You have to enter the message string to encrypt\nPlaintext message:");
                input=sc.nextLine();
            }
            else input =args[0];

            Keys keys = keyGeneration();

            System.out.println("Public Key generated - " + keys.getPublicKey());
            System.out.println("Private Key generated - " + keys.getPrivateKey());

            BigInteger[] rsaPairs = generatingKeyPairs(keys.getPublicKey(), keys.getPrivateKey());

            System.out.println("\n\nKey pairs generated are as follows - ");
            System.out.println("Public Key Modulus : " + rsaPairs[0]);
            System.out.println("Public Key Exponent : " + rsaPairs[1]);
            System.out.println("Private Key Modulus : " + rsaPairs[2]);
            System.out.println("Private Key Exponent : " + rsaPairs[3]);


            //Encrypt Data using Public Key
            byte[] encryptedData = encryptData(input, keys.getPublicKey());

            //Descypt Data using Private Key
            decryptData(encryptedData, keys.getPrivateKey());

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

    private static Keys keyGeneration() {
        System.out.println("Generating Public and Private keys");
        PublicKey publicKey=null;
        PrivateKey privateKey=null;
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }catch (NoSuchAlgorithmException e){
            System.out.print("Exception!!"+e);
            e.printStackTrace();
        }
        Keys k =new Keys(publicKey,privateKey);
        return k;
    }

    public static byte[] encryptData(String data, PublicKey publicKey) throws IOException {
        System.out.println("\n----------------ENCRYPTION STARTED------------");
        System.out.println("Data Before Encryption :" + data);
        byte[] dataToEncrypt = data.getBytes();
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
            System.out.println("Encryted Data: " + encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("----------------ENCRYPTION COMPLETED------------");
        return encryptedData;
    }

    public static void decryptData(byte[] data, PrivateKey privateKey) throws IOException {
        System.out.println("\n----------------DECRYPTION STARTED------------");
        byte[] descryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            descryptedData = cipher.doFinal(data);
            System.out.println("Decrypted Data: " + new String(descryptedData));

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("----------------DECRYPTION COMPLETED------------");
    }

}
