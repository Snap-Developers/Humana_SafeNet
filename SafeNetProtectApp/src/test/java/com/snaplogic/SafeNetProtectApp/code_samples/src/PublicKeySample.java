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
import com.ingrian.security.nae.*;
import com.ingrian.internal.config.Config;
import com.ingrian.internal.cache.*;
import java.util.*;


/**
 * This sample shows how to encrypt and decrypt data using Ingrian JCE provider.
 */

public class PublicKeySample 
{
    public static void main( String[] args ) throws Exception
    {
	/*if (args.length != 3)
        {
            System.err.println("Usage: java PublicKeySample user password keyname");
            System.exit(-1);
	} */
        String username  = "snapuser";//args[0];
        String password  = "1Sn@pL0g1c15";//args[1];
        String keyName   = "snapkey1";//args[2];
        PublicKeySample sample = new PublicKeySample();

	// add Ingrian provider to the list of JCE providers
	Security.addProvider(new IngrianProvider());

	// get the list of all registered JCE providers
	Provider[] providers = Security.getProviders();
	for (int i = 0; i < providers.length; i++)
	    System.out.println(providers[i].getInfo());

	String dataToEncrypt = "94E2050455253495354454E54204346EB17960";
	System.out.println("Data to encrypt \"" + dataToEncrypt + "\"");

	try {
	    // create NAE Session: pass in NAE user name and password
            
            MyNAEKeyCachePassphrase m = sample.new MyNAEKeyCachePassphrase();
            
	    NAESession session  = 
		NAESession.getSession(username, password.toCharArray(), m.getPassphrase(null));

	    // Get SecretKey (just a handle to it, key data does not leave the server
            System.out.println("KEYNAME === " + keyName);
            NAEPublicKey key = NAEKey.getPublicKey(keyName, session );
	    
	    // get a cipher
	    Cipher cipher = Cipher.getInstance("RSA", "IngrianProvider");
	    // initialize cipher to encrypt.
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    // encrypt data
	    byte[] outbuf = cipher.doFinal(dataToEncrypt.getBytes());
	    

            // get private key to decrypt data
            // (just a key handle , key data does not leave the server)
            NAEPrivateKey privKey = NAEKey.getPrivateKey(keyName, session);
            // to decrypt data, initialize cipher to decrypt
            cipher.init(Cipher.DECRYPT_MODE,  privKey);

	    // decrypt data
	    byte[] newbuf = cipher.doFinal(outbuf);
	    System.out.println("Decrypted data  \"" + new String(newbuf) + "\"");

            LocalKey.printCachingDetails();

            if (Config.s_persistCacheEnabled) {
                Thread.sleep(1000);

                System.out.println("Reading cache from disk to read");
                PersistentCache p = new PersistentCache();
                ConcurrentEncryptingHashMap map =
                    p.readFromDisk(username,key.getSession().getPassphrase());
                if (map != null) {
                    System.out.println("Size cache from disk is = " + map.size());
                    Set set = map.keySet();
                    Iterator<String> iter = set.iterator();
                    while (iter.hasNext()) {
                        String o = iter.next();
                        System.out.println("Key cache from disk = " + o);
                        NAECachedKey n = (NAECachedKey)map.get(o, NAECachedKey.class);
                    }
                } else {
                    System.out.println("Map from disk is null");
                }
            }



            session.closeSession();
	} catch (Exception e) {
            e.printStackTrace();
	    System.out.println("The Cause is " + e.getMessage() + ".");
	    throw e;
	} 
    }

    class MyNAEKeyCachePassphrase implements NAEKeyCachePassphrase {

        public char[] getPassphrase(NAESessionInterface session) {
            char[] passPhrase = new char[8];

            passPhrase[0] = 'a';
            passPhrase[1] = 'b';
            passPhrase[2] = 'b';
            passPhrase[3] = '1';
            passPhrase[4] = '2';
            passPhrase[5] = '4';
            passPhrase[6] = '7';
            passPhrase[7] = 'z';
            return passPhrase;
        }
    }

}       
