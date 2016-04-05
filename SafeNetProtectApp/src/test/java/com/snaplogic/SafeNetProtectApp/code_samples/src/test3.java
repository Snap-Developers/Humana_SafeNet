package com.snaplogic.SafeNetProtectApp.code_samples.src;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;

public class test3 {


	// see the examples like AESGCMEncryptionDecryptoinSample, PublicKeySample, CertSample and pages in doc from 85..
		public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
			// TODO Auto-generated method stub
			
			java.security.Security.addProvider(new IngrianProvider());
			
			// get the list of all registered JCE providers
			Provider[] providers = Security.getProviders();
			for (int i = 0; i < providers.length; i++)
			    System.out.println(providers[i].getInfo());
			
			//get session by user name
			String uname="snapuser";
			String pwd = "1Sn@pL0g1c15";
			NAESession session = NAESession.getSession(uname, pwd.toCharArray());//, "hello".toCharArray());
			
			NAEKey secretKey = NAEKey.getSecretKey("snapkey128", session);
			
			//NAEKey secretKey = NAEKey.getSecretKey("snapkey1", session);
			System.out.println("Algorithm:"+secretKey.getAlgorithm());
			
			Cipher cipher = Cipher.getInstance("AES", "IngrianProvider");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			
			byte[] ciphertext = cipher.doFinal("Hello World!".getBytes());
			
			System.out.println(ciphertext);
			
		}


}
