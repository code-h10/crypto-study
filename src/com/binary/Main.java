package com.binary;

import com.binary.crypto.CryptoUtil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

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

    }
}
