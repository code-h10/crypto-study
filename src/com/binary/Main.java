package com.binary;

import com.binary.crypto.CryptoUtil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    private static final String salt = "rwZzlR1UFxDEonMqTLNOzQ==";
    private static final String password = ">uL(0(J${j/JCQ}l";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        SecretKey securityKey = CryptoUtil.generateKeyFromPassword(password, salt);
        IvParameterSpec ivParameterSpec = CryptoUtil.generateIv();

        String input = "HelloWorld";
        String cipherText = CryptoUtil.encryptWithAES(input, securityKey, ivParameterSpec);
        System.out.println(cipherText);

        String plainText = CryptoUtil.decryptWithAES(cipherText, securityKey, ivParameterSpec);
        System.out.println(plainText);

        SecretKey hamcSecretKey = CryptoUtil.generateKeyWithString("1234");
        String hmacText = CryptoUtil.generateHmacSHA256(input, hamcSecretKey);
        System.out.println(hmacText);

    }
}
