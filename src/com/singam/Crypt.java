package com.singam;

import javax.crypto.*;
import java.security.*;

public class Crypt{
    public PublicKey publicKey;
    public PrivateKey privateKey;
    public String sessionKey;


    public Crypt() throws NoSuchAlgorithmException {

        KeyPair keyPair = this.buildKeyPairRsa();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();

    }


    public KeyPair buildKeyPairRsa() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
    public void setPublicKey(PublicKey publicKey){
        this.publicKey = publicKey;
    }

    public void setSessionKey(String sessionKey){
        this.sessionKey = sessionKey;
    }


    public byte[] encryptRC4(String toEncrypt) throws Exception {
        // create a binary key from the argument key (seed)
        SecureRandom sr = new SecureRandom(this.sessionKey.getBytes());
        KeyGenerator kg = KeyGenerator.getInstance("RC4");
        kg.init(sr);
        SecretKey sk = kg.generateKey();

        // create an instance of cipher
        Cipher cipher = Cipher.getInstance("RC4");

        // initialize the cipher with the key
        cipher.init(Cipher.ENCRYPT_MODE, sk);

        // enctypt!
        byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
        //System.out.println("ENCED"+this.sessionKey+"|"+new String(encrypted));
        return encrypted;
    }

    public String decryptRC4(byte[] toDecrypt) throws Exception {
        // create a binary key from the argument key (seed)
        SecureRandom sr = new SecureRandom(this.sessionKey.getBytes());
        KeyGenerator kg = KeyGenerator.getInstance("RC4");
        kg.init(sr);
        SecretKey sk = kg.generateKey();

        // do the decryption with that key
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.DECRYPT_MODE, sk);
        //System.out.println("DCED|"+this.sessionKey+"|"+new String(toDecrypt));
        byte[] decrypted = cipher.doFinal(toDecrypt);

        return new String(decrypted);
    }

    public byte[] encryptRsa(String message) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PUBLIC_KEY, publicKey);

        return cipher.doFinal(message.getBytes());
    }

    public byte[] decryptRsa( byte [] encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
       // System.out.println(encrypted.length);
        return cipher.doFinal(encrypted);
    }



}