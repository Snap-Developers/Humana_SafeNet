package com.snaplogic.SafeNetProtectApp.code_samples.src;
/*
 * $URL:$	%E% %U%	Safenet, Inc.
 * Copyright (C) 2008-2010 Safenet, Inc.
 */

// Standard JCE classes. 
import java.security.Security;
import java.security.Provider;

import javax.crypto.SecretKey;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;

import com.ingrian.security.nae.IngrianProvider;
// Ingrian specific JCE classes.
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import com.ingrian.security.nae.NAESecureRandom;

/**
 * This sample shows how to encrypt and decrypt data using Ingrian JCE provider.
 */

public class SecretKeyEncryptionSample 
{
    public static void main( String[] args ) throws Exception
    {
	/*if (args.length != 3)
        {
            System.err.println("Usage: java SecretKeyEncryptionSample user password keyname");
            System.exit(-1);
	} */
	 String username  = "snapuser";//args[0];
     String password  = "1Sn@pL0g1c15";//args[1];
     String keyName   = "snapkey1";//args[2];

	// add Ingrian provider to the list of JCE providers
	Security.addProvider(new IngrianProvider());

	// get the list of all registered JCE providers
	Provider[] providers = Security.getProviders();
	for (int i = 0; i < providers.length; i++)
	    System.out.println(providers[i].getInfo());

	String dataToEncrypt = "2D2D2D2D2D424547494E2050455253495354454E54204346EB17960";
	System.out.println("Data to encrypt \"" + dataToEncrypt + "\"");

	try {
	    // create NAE Session: pass in NAE user name and password
	    NAESession session  = 
		NAESession.getSession(username, password.toCharArray());

	    // Get SecretKey (just a handle to it, key data does not leave the server
	    NAEKey key = NAEKey.getSecretKey(keyName, session);
	    
	    // get IV
	    NAESecureRandom rng = new NAESecureRandom(session);

	    byte[] iv = new byte[16];
	    rng.nextBytes(iv);
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    
	    // get a cipher
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
	    // initialize cipher to encrypt.
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	    // encrypt data
	    byte[] outbuf = cipher.doFinal(dataToEncrypt.getBytes());
	    

	    // to decrypt data, initialize cipher to decrypt
	    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	    // decrypt data
	    byte[] newbuf = cipher.doFinal(outbuf);
	    System.out.println("Decrypted data  \"" + new String(newbuf) + "\"");

	    // to encrypt data in the loop
	    Cipher loopCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
	    // initialize cipher to encrypt.
	    loopCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	    byte[] outbuffer = null;
	    for (int i = 0; i < 10; i++) {
		// encrypt data in the loop 
		outbuffer = loopCipher.doFinal(dataToEncrypt.getBytes());
	    }

	    // to decrypt data in the loop
	    // initialize cipher to decrypt.
	    loopCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	    byte[] decrBuffer = null;
	    for (int i = 0; i < 10; i++) {
		// decrypt data in the loop 
		decrBuffer = loopCipher.doFinal(outbuffer);
	    }

	    // close the session
	    session.closeSession();
	} catch (Exception e) {
	    System.out.println("The Cause is " + e.getMessage() + ".");
	    throw e;
	} 
    }
}
    
