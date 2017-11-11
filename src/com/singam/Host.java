package com.singam;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class Host {

    static DatagramSocket sock = null;
    static Crypt cr;
    static int port = 7777;
    static InetAddress host;
    static BufferedReader cin ;
    static DatagramPacket incoming;
    static boolean isReady = false;

    public static void main(String[] args) {

        init();

        while (true) {
            Message m = recvMsg();
            switch (m.getId()){
                case Message.INIT:
                    echo("CLIENT CONNECTION");
                    sendMsg(Message.PKEY, Base64.getEncoder().encodeToString(cr.publicKey.getEncoded()),false);
                    break;
                case Message.SESSION:
                    echo("SESSION RECIEVED");
                    String sessionKey  = null;
                    try {
                        sessionKey = new String(cr.decryptRsa(Base64.getDecoder().decode(m.getMsg())));
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
                    cr.setSessionKey(sessionKey);
                    sendMsg(Message.ACKSESSION,"x",false);
                    break;
                case Message.AUTH:
                    String password = null;
                    try {
                       password = new String(cr.decryptRC4(Base64.getDecoder().decode(m.getMsg())));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    if(password.compareTo(getPw())==0){
                        sendMsg(Message.READY,"x",false);
                        echo("Ready for communication");
                        isReady = true;
                    }else{
                        echo("AUTH failed");
                        sendMsg(Message.NOT_READY,"x",false);
                    }
                    break;
                case Message.CHAT:
                    m.sign(cr.sessionKey);
                    if(m.verify(cr.sessionKey)){
                        echo(m.getMsg());
                    }else{
                        echo("Bad message discarding");
                    }
            }


            if (isReady) {
                echo("Enter message to send : ");
                String mn = null;
                try {
                    mn = (String) cin.readLine();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                sendMsg(Message.CHAT, mn, true);
            }
        }

    }

    public static void echo(String msg)
    {
        System.out.println(msg);
    }


    public static void saveKeys(){
        PrintWriter writer = null;
        try {
            writer = new PrintWriter("rsa_key_server.txt", "UTF-8");
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


    public static Message recvMsg(){
        try {
            sock.receive(incoming);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] data = incoming.getData();
        String tmp = new String(data, 0, incoming.getLength());
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

        DatagramPacket dpc = new DatagramPacket(b, b.length, incoming.getAddress(), incoming.getPort());
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
        byte[] buffer = new byte[65536];
        incoming = new DatagramPacket(buffer, buffer.length);
        try {
            sock = new DatagramSocket(7777);
        } catch (SocketException e) {
            e.printStackTrace();
        }
        saveKeys();
        echo("Server socket created. Waiting for incoming data...");
    }
}
