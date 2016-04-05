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
import com.ingrian.internal.cache.*;
import com.ingrian.internal.config.*;
import java.util.*;


/**
 * This sample shows how to encrypt and decrypt data using Ingrian JCE provider.
 */

public class CachingSample 
{
    public static void main( String[] args ) throws Exception
    {
	/*if (args.length != 3)
        {
            System.err.println("Usage: java CachingSample user password keyname");
            System.exit(-1);
	}*/ 
        String username  = "snapuser";
        String password  = "1Sn@pL0g1c15";
        String keyName   = "snapkey1";
        CachingSample sample = new CachingSample();

	// add Ingrian provider to the list of JCE providers
	Security.addProvider(new IngrianProvider());

	// get the list of all registered JCE providers
	Provider[] providers = Security.getProviders();
	for (int i = 0; i < providers.length; i++)
	    System.out.println(providers[i].getInfo());

	String dataToEncrypt = "1234567812345678";
	System.out.println("Data to encrypt \"" + dataToEncrypt + "\"");

	try {
	    // create NAE Session: pass in NAE user name and password
            
            MyNAEKeyCachePassphrase m = sample.new MyNAEKeyCachePassphrase();
            
	    NAESession session  = 
		NAESession.getSession(username, password.toCharArray(), m.getPassphrase(null));

	    // Get SecretKey (just a handle to it, key data does not leave the server

            System.out.println("KEYNAME === " + keyName);
          /*  sample.oneShotEncrypt(session, keyName, "AES/CBC/NoPadding",dataToEncrypt, "1234567812345678" );
            sample.oneShotEncrypt(session, keyName, "AES/CBC/PKCS5Padding",dataToEncrypt, "1234567812345678" );
            sample.oneShotEncrypt(session, keyName, "AES/CBC/PKCS5Padding",dataToEncrypt, null );*/
            sample.oneShotEncrypt(session, keyName, "AES/ECB/PKCS5Padding",dataToEncrypt, null );
            sample.oneShotEncrypt(session, keyName, "AES/ECB/NoPadding",dataToEncrypt, null );



            LocalKey.printCachingDetails();
            Thread.sleep(1000);

            System.out.println("Reading cache from disk to read");
            PersistentCache p = new PersistentCache();
            ConcurrentEncryptingHashMap map = 
                p.readFromDisk(username, session.getPassphrase());
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
            session.closeSession();
	} catch (Exception e) {
            e.printStackTrace();
	    System.out.println("The Cause is " + e.getMessage() + ".");
	    throw e;
	} 
    }

    public void oneShotEncrypt(
       NAESession session,
       String keyname,
       String algorithm,
       String plainText,
       String ivStr) 
    {
       Cipher cipher = null;
       try {
           NAEKey pkey = NAEKey.getSecretKey(keyname, session);
           cipher = Cipher.getInstance(algorithm, "IngrianProvider");
           if (ivStr == null) {
               cipher.init(Cipher.ENCRYPT_MODE, pkey);
               byte[] outbuf = cipher.doFinal(plainText.getBytes());
	       cipher.init(Cipher.DECRYPT_MODE, pkey);
	       byte[] newbuf = cipher.doFinal(outbuf);
	       System.out.println("Decrypted data  \"" + new String(newbuf) + "\"");
           } else {
              byte [] iv = ivStr.getBytes();
              IvParameterSpec ivSpec = new IvParameterSpec(iv);
              cipher.init(Cipher.ENCRYPT_MODE, pkey, ivSpec);
              byte[] outbuf = cipher.doFinal(plainText.getBytes());
              cipher.init(Cipher.DECRYPT_MODE, pkey, ivSpec);
	      byte[] newbuf = cipher.doFinal(outbuf);
	      System.out.println("Decrypted data  \"" + new String(newbuf) + "\"");
           }
       } catch (Exception e) {
           e.printStackTrace();
           System.out.println("Exception = " + e);
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
