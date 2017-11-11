package com.singam;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class Client {

    static DatagramSocket sock = null;
    static Crypt cr;
    static int port = 7777;
    static InetAddress host;
    static BufferedReader cin ;
    static boolean isReady = false;


    public static void main(String[] args) {
        init();
        sendMsg(Message.INIT,"x",false);

        while (true) {
            Message m = recvMsg();
            switch (m.getId()){
                case Message.PKEY:
                    String publicKey = m.getMsg();
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
                    KeyFactory kf = null;
                    try {
                        kf = KeyFactory.getInstance("RSA");
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                    PublicKey pubKeyString = null;
                    try {
                        pubKeyString = kf.generatePublic(spec);
                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    }
                    cr.setPublicKey(pubKeyString);
                    cr.setSessionKey(new String(makeSession()));
                    String enc = null;
                    try {
                        enc = Base64.getEncoder().encodeToString(cr.encryptRsa(cr.sessionKey));
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }
                    sendMsg(Message.SESSION,enc,false);
                    break;
                case Message.ACKSESSION:
                    String enc1 = null;
                    try {
                        enc1 = Base64.getEncoder().encodeToString(cr.encryptRC4(getPw()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    sendMsg(Message.AUTH,enc1,false);
                    break;
                case Message.READY:
                    echo("Ready for communication");
                    isReady = true;
                    break;
                case Message.NOT_READY:
                    echo("Not ready AUTH failed");
                    break;
                case Message.CHAT:
                    m.sign(cr.sessionKey);
                    if(m.verify(cr.sessionKey)){
                        echo(m.getMsg());
                    }else{
                        echo("Bad message discarding");
                    }
            }

            if(isReady){
                echo("Enter message to send : ");
                String mn = null;
                try {
                    mn = (String)cin.readLine();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                if(mn.compareTo("exit") == 0){
                    System.exit(0);
                }
                else{
                    sendMsg(Message.CHAT,mn,true);
                }

            }
        }


    }

    public static void saveKeys(){
        PrintWriter writer = null;
        try {
            writer = new PrintWriter("rsa_key_client.txt", "UTF-8");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        writer.println(Base64.getEncoder().encodeToString(cr.publicKey.getEncoded()));
        writer.println("----------------------");
        writer.println(Base64.getEncoder().encodeToString(cr.privateKey.getEncoded()));
        writer.close();
    }

    public static void echo(String msg)
    {
        System.out.println(msg);
    }

    public static byte[] makeSession(){
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] session = new byte[100];
        new Random().nextBytes(session);
        String tmp = new String(session);
        tmp = tmp + getPw();
        session = tmp.getBytes();
        session = md.digest(session);
        return session;
    }

    public static Message recvMsg(){
        byte[] buffer = new byte[65536];
        DatagramPacket reply = new DatagramPacket(buffer, buffer.length);
        try {
            sock.receive(reply);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] data = reply.getData();
        String tmp = new String(data, 0, reply.getLength());
        String parts[] = tmp.split(" ",2);
        int code = Integer.parseInt(parts[0]);

        if(code == Message.SIGNED){
            String[] tmp2 = parts[1].split(" ",2);
            return new Message(code,tmp2[0],tmp2[1]);
        }
        else{
            return new Message(code,parts[1]);
        }
    }

    public static void sendMsg(int id,String msg,boolean sign){
        Message m = new Message(id,msg);
        if(sign){
            m.sign(cr.sessionKey);
            msg = m.packTo(true);
        }else{
            msg = m.packTo(false);
        }
        byte[] b = msg.getBytes();
        DatagramPacket dpc = new DatagramPacket(b, b.length, host, port);
        try {
            sock.send(dpc);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String getPw(){
        String pw = "key123";
        Scanner file = null;
        try {
            file = new Scanner(new File("keyc.txt"));
            pw = file.nextLine();
            file.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Unable to detect password for user.\nTerminating Session");
        }
        return pw;
    }

    public static void init(){
        cin = new BufferedReader(new InputStreamReader(System.in));
        try {
            cr = new Crypt();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sock = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        try {
            host = InetAddress.getByName("localhost");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        saveKeys();
    }
}
