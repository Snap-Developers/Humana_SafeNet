package com.snaplogic.SafeNetProtectApp.code_samples.src;


import com.ingrian.security.nae.*;

import java.math.BigInteger;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


public class TestPrgWithIV {
// see the examples like AESGCMEncryptionDecryptoinSample, PublicKeySample, CertSample and pages in doc from 85..
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		final int HEX_RADIX = 16;
		NAESession session=null;
		
		java.security.Security.addProvider(new IngrianProvider());
		
		//get session by user name
		String uname="snapuser";
		String pwd = "1Sn@pL0g1c15";
		session = NAESession.getSession(uname, pwd.toCharArray());//, "hello".toCharArray());
		
		NAEKey secretKey = NAEKey.getSecretKey("snapkey1abc", session);
		System.out.println("Algorithm:"+secretKey.getAlgorithm());
		
		//NAESecureRandom rng = new NAESecureRandom (session);
		
		/*SecureRandom sr = SecureRandom.getInstance("IngrianRNG", "IngrianProvider");
		byte[] iv = new byte[16];
		sr.nextBytes(iv);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		*/
		
		String initializationVector = "12345678123456781234567812345678";
		byte[] ivParameterBytes = new BigInteger(initializationVector, HEX_RADIX)
        .toByteArray();
		IvParameterSpec ivSpec = new IvParameterSpec(ivParameterBytes);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
		
		byte[] encryptedText = cipher.doFinal("Hello World!".getBytes());
		 System.out.println("encrypted data data  \"" + new String(encryptedText) + "\"");
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey/*,ivSpec*/);
		
		byte[] decriptedText = cipher.doFinal(encryptedText);
	    System.out.println("Decrypted data  \"" + new String(decriptedText) + "\"");
		
		
	
		
		
	}

}
