package com.binary.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CryptoUtil {

    /**
     * Encrypt PlainText With AES
     * @author IlYoungHwang
     * @param plainText
     * @param key
     * @param iv
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public static String encryptWithAES(String plainText, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException
                                                                                            , NoSuchAlgorithmException
                                                                                            , IllegalBlockSizeException
                                                                                            , BadPaddingException
                                                                                            , InvalidAlgorithmParameterException
                                                                                            , InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     *
     * @author IlYoungHwang
     * @param cipherText
     * @param key
     * @param iv
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decryptWithAES(String cipherText, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException
                                                                                                    , NoSuchAlgorithmException
                                                                                                    , InvalidAlgorithmParameterException
                                                                                                    , InvalidKeyException
                                                                                                    , BadPaddingException
                                                                                                    , IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }


    /**
     * 함호화 키 길이 n 의 값을 받아 단순한 SecretKey 생성
     * @author IlYoungHwang
     * @param n
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoAlgorithm.AES.name());
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     *
     * password, salt 값을 받아 HMAC(SHA256) 해시 함수를 적용한 SecretKey 생성
     * @author IlYoungHwang
     * @param password
     * @param salt
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeySpecException
     */
    public static SecretKey generateKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException
                                                                                    , InvalidKeySpecException
                                                                                    , InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), CryptoAlgorithm.AES.name());
        return secret;
    }


    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * 무작위 16 byte Salt 값 생성
     * 한번 생상한 값은 분실하지 않도록 주의해야됨
     * @author IlYoungHwang
     * @return
     */
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * 일반적으로 아래와 같은 조건으로 안전하게 생성해야함, 스터디용으로 랜덤으로 생성함
     *  - 최소 8자 이상
     *  - 대문자, 소문자, 숫자, 특수문자 중 3가지 이상 조합
     *  - 일반적으로 사용되는 단어나 개인 정보 (예 : 생일, 전화번호 등) 사용하지 않기
     * 한번 생상한 값은 분실하지 않도록 주의해야됨
     * @author IlYoungHwang
     * @return
     */
    public static String generatePassword() {
        SecureRandom random = new SecureRandom();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{};:<>,.?/~";
        int passwordLength = 16;
        char[] password = new char[passwordLength];

        for (int i = 0; i < passwordLength; i++) {
            password[i] = characters.charAt(random.nextInt(characters.length()));
        }

        return String.valueOf(password);
    }
}
