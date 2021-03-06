package com.singam;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Message {
    public static final int  ACKSESSION = 0;
    public static final int READY = 1;
    public static final int SIGNED = 2;
    public static final int PKEY = 3;
    public static final int SESSION = 4;
    public static final int AUTH = 5;
    public static final int NOT_READY = 6;
    public static final int CHAT = 7;
    public static final int INIT = 8;


    private int id = 0;
    private String msg = "";
    private String sign = null;

    public Message(int id,String msg){
        this.msg = msg;
        this.id = id;
    }

    public Message(int id,String msg, String sign){
        this.msg = msg;
        this.id = id;
        this.sign = sign;
    }

    public void sign(String session){
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.sign = new String(md.digest((session + this.msg + session).getBytes()));
    }

    public String getMsg(){
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public int getId(){
        return id;
    }

    public String getSign(){
        return sign;
    }

    public String packTo(boolean sign){
        String packed = "";
        if(sign){
            packed = packed+id+" "+sign+" "+msg;
        }else{
            packed = packed+id+" "+msg;
        }
        return packed;
    }

    public boolean verify(String session){
        boolean verified = false;

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String sign2 = new String(md.digest((session + this.msg + session).getBytes()));
        if(sign2.compareTo(this.sign)== 0){
            verified = true;
        }
        return verified;
    }
}
