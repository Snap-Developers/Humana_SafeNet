package com.snaplogic.SafeNetProtectApp.code_samples.src;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;

public class Test_AES_128 {

	public static void main(String[] args) throws Exception
	{
	    String input = JOptionPane.showInputDialog(null, "Enter your String");
	    System.out.println("Plaintext: " + input + "\n");

	    // Generate a key
	    KeyGenerator keygen = KeyGenerator.getInstance("AES");
	    keygen.init(128); 
	    byte[] key = keygen.generateKey().getEncoded();
	    SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

	    // Generate IV randomly
	    SecureRandom random = new SecureRandom();
	    byte[] iv = new byte[16];
	    random.nextBytes(iv);
	    IvParameterSpec ivspec = new IvParameterSpec(iv);

	/*    String uname="snapuser";
		String pwd = "1Sn@pL0g1c15";
		NAESession session = NAESession.getSession(uname, pwd.toCharArray());
		//cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		NAEKey secretKey = NAEKey.getSecretKey("snapkey1", session);
		//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
*/	    
	    
	    // Initialize Encryption Mode
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);

	    // Encrypt the message
	    byte[] encryption = cipher.doFinal(input.getBytes());
	    System.out.println("Ciphertext: " + encryption + "\n"); //

	    // Initialize the cipher for decryption
	    cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);

	    // Decrypt the message
	    byte[] decryption = cipher.doFinal(encryption);
	    System.out.println("Plaintext: " + new String(decryption) + "\n");
	}

}
