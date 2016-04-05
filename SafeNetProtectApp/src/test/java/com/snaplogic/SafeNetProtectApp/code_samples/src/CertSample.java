package com.snaplogic.SafeNetProtectApp.code_samples.src;
/*
 * $URL:$	%E% %U%	Safenet, Inc.
 * Copyright (C) 2009-2010 Safenet, Inc.
 */

// Standard JCE classes. 
import java.io.FileInputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.NAECertificate;
import com.ingrian.security.nae.NAEParameterSpec;
import com.ingrian.security.nae.NAESession;
import com.ingrian.security.nae.*;

/**
 * This sample shows how to use different certificate operations:
 * import and export certificate and its private key (if present);
 * export CA certificate and certificate chain. The imported 
 * certificates must be in either PKCS#1, PKCS#8, or PKCS#12 format. 
 * If encrypted, PKCS#12 certificates must be encrypted with 3DES.
 * 
 * Included with this sample code are three sample certificates:
 * cert.pkcs1, cert.pkcs8, and cert.pkcs12. To use those samples, 
 * you must first install the signing CA (sample_ca) to your DataSecure 
 * and then add that CA to Trusted CA List used by the Key Server. 
 * The password for cert.pkcs12 is asdf1234. Further instructions 
 * can be found in the ProtectApp-JCE User Guide.
 * 
 * The sample certificates are included as a convenience. You can 
 * also use your own certificates. 
 */

public class CertSample {
    public static void main( String[] args ) throws Exception 
    {
	/*if (args.length < 5) {
            System.err.println("Usage: java CertSample user password fileName certName caName pkcs12Password (pkcs12Password can be null if cert data is in PKCS#1 format)."); 
            System.exit(-1);
    } */
	
    String username   = "snaplogic";//args[0];
    String password   = "1Sn@pL0g1c15";//args[1];
    String fileName   = "";//args[2];
    String certName   = "cert.pkcs8";//args[3];
    String caName     = "";//args[4];
    String pkcs12Pass = null;
    if (args.length == 6)
    	pkcs12Pass = args[5];

	try {
		NAEClientCertificate clientCert = new NAEClientCertificate("testCert", password);
		
	    // create NAE Session: pass in NAE user name and password
	    NAESession session = NAESession.getSession(username, password.toCharArray());

	    // import the certificate with corresponding private key 
	    // from the file to DataSecure

	    FileInputStream fis = new FileInputStream(fileName);
	    byte[] certData = new byte[fis.available()];
	    fis.read(certData);
	    fis.close();

	    NAEParameterSpec spec = new NAEParameterSpec(certName, true, true,  session);
	    // If cert data is in PKCS#1 format, pass in 'null' for password
	    NAECertificate.importCertificate(certData, null, spec);
	    // if cert data is in PKCS#12 format, pass in password
	//     NAECertificate.importCertificate(certData, pkcs12Pass.toCharArray(), spec);
	    
	    // export back this certificate and its private key
	    NAECertificate cert = new NAECertificate (certName, session);
	    byte[] exportCertKeyData = cert.export("PEM-PKCS#8", null);

	    // export back this certificate (without private key)
	    byte[] exportCertData = cert.certificateExport();

	    // get cert info from the DataSecure
	    if (cert.isDeletable())
		System.out.println("Cert deletable"); 
	    System.out.println("Algorithm: " + cert.getAlgorithm());

	    // delete the certificate from the DataSecure
	    cert.delete();

	    // export CA certificate and its cert chain (if present)
	    byte[] exportCAData = NAECertificate.CACertificateExport(caName, session);

	} catch (Exception e) {
	    e.printStackTrace();
	    System.out.println("Exception " + e.getMessage());
	} 
    }
}
