package com.snaplogic.SafeNetProtectApp.code_samples.src;



import com.ingrian.security.nae.*;
import com.snaplogic.api.ExecutionException;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


public class TestPrg {
// see the examples like AESGCMEncryptionDecryptoinSample, PublicKeySample, CertSample and pages in doc from 85..
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		
		NAESession session=null;
		
		//System.setProperty("com.ingrian.security.nae.NAE_IP.1", "10.20.1.9");
	/*	System.setProperty("com.ingrian.security.nae.NAE_IP.1", "192.168.22.120");
		System.setProperty("com.ingrian.security.nae.NAE_Port","9000");
		System.setProperty("com.ingrian.security.nae.Protocol","tcp");*/
		
	/*	System.setProperty("com.ingrian.security.nae.NAE_IP.1", "192.43.161.38");
		System.setProperty("com.ingrian.security.nae.Protocol","tcp");
		System.setProperty("com.ingrian.security.nae.NAE_Port","9000");*/
		java.security.Security.addProvider(new IngrianProvider());
		
		//get session by certificate
	/*	NAEClientCertificate clientCert = new NAEClientCertificate("Cert2", "Cert2-Password");
		session = NAESession.getSession(clientCert);
		
		if(session==null){
			throw new NullPointerException();
		}*/
		//get session by user name
		String uname="snapuser";
		String pwd = "1Sn@pL0g1c15";
		session = NAESession.getSession(uname, pwd.toCharArray());//, "hello".toCharArray());
		//NAESession.getSession()
		NAEKey secretKey = null;
		try{
			secretKey = NAEKey.getSecretKey("snapkey1aaaa", session);
			System.out.println("Algorithm:"+secretKey.getAlgorithm());	
		}catch(Exception ex){
			System.out.println("Invalid key:"+ex.getMessage());
		} /*catch (InvalidKeyException e) {
           
}*/
		
		//look into the page 89
		
		//this ECB not accepts IV
		//Cipher cipher = Cipher.getInstance("AES", "IngrianProvider");
		/*String ivStr = "1234567812345678";
		 byte [] iv = ivStr.getBytes();
         IvParameterSpec ivSpec = new IvParameterSpec(iv);*/
		
		Cipher cipher = Cipher.getInstance("AES/ECB/NOPadding", "IngrianProvider");
		//Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "IngrianProvider");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		byte[] encryptedText = cipher.doFinal("1234567812345678".getBytes());  // or use 1234567812345678 as text
		//System.out.println(ciphertext);
		 System.out.println("encrypted data data  \"" + new String(encryptedText) + "\"");
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		
		byte[] decriptedText = cipher.doFinal(encryptedText);
	    System.out.println("Decrypted data  \"" + new String(decriptedText) + "\"");
		
		//adding IV parameter for CBC
		NAESecureRandom rng = new NAESecureRandom (session);
		
	    byte[] iv = new byte[16];
	    rng.nextBytes(iv);
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		
		//Cipher cipher = Cipher.getInstance("AES/CBC/NOPadding", "IngrianProvider");
	/*	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
		
		byte[] encryptedText = cipher.doFinal("Hello World!".getBytes());
		//System.out.println(ciphertext);
		 System.out.println("encrypted data data  \"" + new String(encryptedText) + "\"");
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey,ivSpec);
		
		byte[] decriptedText = cipher.doFinal(encryptedText);
	    System.out.println("Decrypted data  \"" + new String(decriptedText) + "\"");*/
		
		
	
		
		
	}

}
