package com.snaplogic.SafeNetProtectApp.code_samples.src;
/*
 * $URL:$	%E% %U%	Safenet, Inc.
 * Copyright (C) 2008-2010 Safenet, Inc.
 */

// Standard JCE classes. 
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.Provider;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileOutputStream;
import java.io.FileInputStream;

import com.ingrian.security.nae.IngrianProvider;
// Ingrian specific JCE classes.
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.NAESecureRandom;
/**
 * This sample shows how to encrypt and decrypt file using Ingrian JCE provider.
 */
public class FileEncryptionSample {
        public static void main( String[] args ) throws Exception
    {
	/*if (args.length != 6)
        {
            System.err.println
		("Usage: java FileEncryptionSample user password keyname fileToEncrypt encryptedFile decryptedFile");
            System.exit(-1);
	} */
        String username  = "snapuser";//args[0];
        String password  = "1Sn@pL0g1c15";//args[1];
        String keyName   = "snapkey1";//args[2];
	String srcName   = "/home/gaian/Downloads/filterdata";
			//"/home/gaian/Desktop/deploy-commands-fullsail";//args[3];
	String dstName   = "/home/gaian/Desktop/test1.txt";//args[4];
	String decrName  = "test file";//args[5];
	
	// how many bytes of data to read from the input stream - can be any size
	int BUFSIZE = 512;

	// add Ingrian provider to the list of JCE providers
	Security.addProvider(new IngrianProvider());

	// get the list of all registered JCE providers
	Provider[] providers = Security.getProviders();
	for (int i = 0; i < providers.length; i++)
	    System.out.println(providers[i].getInfo());

	try {
	    // create NAE Session: pass in NAE user name and password
	    NAESession session  = 
		NAESession.getSession(username, password.toCharArray());

	    // Get SecretKey (just a handle to it, key data does not leave the server
	    NAEKey key = NAEKey.getSecretKey(keyName, session);
	    
	    // get IV
	    NAESecureRandom rng = new NAESecureRandom (session);
	
	    byte[] iv = new byte[16];
	    rng.nextBytes(iv);
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    
	    Cipher.getMaxAllowedKeyLength( "AES/CBC/PKCS5Padding" );
	    
	    // get a cipher
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");

	    // initialize cipher to encrypt.
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

	    // create CipherInputStream that will read in data from file and encrypt it
	    CipherInputStream cis = new CipherInputStream(new FileInputStream(srcName), cipher);
	    FileOutputStream fos  = new FileOutputStream(dstName);
	    
	    // Read the file as blocks of data
	    byte[] inbuf = new byte[BUFSIZE];
	    for ( int inlen = 0; (inlen = cis.read(inbuf)) != -1;  ) {
		fos.write( inbuf, 0, inlen);
	    }

	    System.out.println("Done encrypting file.  Closing files");
	    cis.close();
	    fos.close();


	    // initialize cipher to decrypt.
	    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

	    // create CipherInputStream that will read in data from file and decrypt it
	    cis = new CipherInputStream(new FileInputStream(dstName), cipher);
	    fos = new FileOutputStream(decrName);

	    for ( int inlen = 0; (inlen = cis.read(inbuf)) != -1;  ) {
		fos.write( inbuf, 0, inlen);
	    }
	    System.out.println("Done decrypting file.  Closing files");
	    cis.close();
	    fos.close();

	    session.closeSession();
	} catch (Exception e) {
	    System.out.println("The Cause is " + e.getMessage() + ".");
	    throw e;
	} 
    }
}
