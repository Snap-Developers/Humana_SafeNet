/*
 * SnapLogic - Data Integration
 *
 * Copyright (C) 2013, SnapLogic, Inc.  All rights reserved.
 *
 * This program is licensed under the terms of
 * the SnapLogic Commercial Subscription agreement.
 *
 * "SnapLogic" is a trademark of SnapLogic, Inc.
 */

package com.snaplogic.snaps.SafeNetProtectApp;

import com.google.inject.Inject;
import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.NAEException;
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import com.snaplogic.account.api.capabilities.Accounts;
import com.snaplogic.api.ConfigurationException;
import com.snaplogic.api.ExecutionException;
import com.snaplogic.api.SnapException;
import com.snaplogic.common.SnapType;
import com.snaplogic.common.properties.builders.PropertyBuilder;
import com.snaplogic.snap.api.BinaryOutput;
import com.snaplogic.snap.api.Document;
import com.snaplogic.snap.api.ErrorViews;
import com.snaplogic.snap.api.PropertyValues;
import com.snaplogic.snap.api.SnapDataException;
import com.snaplogic.snap.api.capabilities.Errors;
import com.snaplogic.snap.api.capabilities.ViewType;
import com.snaplogic.snap.api.transform.SimpleBinaryTransformSnap;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import static com.snaplogic.snaps.SafeNetProtectApp.Messages.*;

/**
 * The Encrypt snap encrypts the binary documents it receives on its input view using the
 * user-specified encryption algorithms.
 *
 * <p>
 * The snap uses the following properties:
 * <ul>
 * <li>Password - string used to generate secret encryption/decryption key</li>
 * <li>Secret key - secret encryption/decryption key</li>
 * <li>Initialization vector - an arbitrary number that can be used along with a secret key for data
 * encryption</li>
 * <li>Cipher mode - mode of operation for a block cipher</li>
 * <li>Padding - padding scheme for a block cipher</li>
 * </ul>
 *
 * @author sprasad
 */
@Accounts(provides = {SymmetricKeyAccount.class})
@Errors(min = 1, max = 1, offers = {ViewType.DOCUMENT})
public abstract class AbstractSymmetricCryptoSnap extends SimpleBinaryTransformSnap {
    private static final String ECB_MODE = "ECB";
    private static final String UNDEFINED_VALUE = "UNDEFINED";
    private static final String SECRET_KEY_PROP = "secretKey";
    private static final String IV_PROP = "initializationVector";
    private static final int HEX_RADIX = 16;
    protected static final String CIPHER_MODE_PROP = "cipherMode";
    protected static final String PADDING_PROP = "cryptoPadding";
    protected String cryptoAlgorithm;
    private String transformation = UNDEFINED_VALUE;
    protected int cryptoMode;
    protected IvParameterSpec ivParameterSpec;
    protected String cipherMode = UNDEFINED_VALUE;
    protected String cryptoPadding = UNDEFINED_VALUE;

    private Cipher cipher;
    private String username;
    private String password;
    private String secretKeyName;
    private NAESession session = null;
	private NAEKey secretKey = null;
	private String initializationVector;

    @Inject
    private SymmetricKeyAccount account;
    @Inject
    private ErrorViews errorViews;
    
    private static final Logger LOGGER = LoggerFactory
			.getLogger(AbstractSymmetricCryptoSnap.class);

    /**
     * Implemented encryption algorithms.
     */
    static enum CryptoAlgorithm {
        AES("AES"); // need to add algorithm names

        private final String name;

        private CryptoAlgorithm(String value) {
            this.name = value;
        }

        public String getName() {
            return this.name;
        }
    }

    /**
     * Cipher mode enum for AES Encrypt and Decrypt snap
     */
    protected static enum AESCipherMode {
        ECB, CBC
    }

    /**
     * Encryption padding enum for AES & Blowfish Encrypt and Decrypt snap
     */
    protected static enum CryptoPadding {
        PKCS5PADDING, NOPADDING
    }

    @Override
    public void defineProperties(PropertyBuilder propertyBuilder) {
        propertyBuilder
                .describe(SECRET_KEY_PROP, CRYPTO_SECRET_KEY_LABEL, CRYPTO_SECRET_KEY_DESC)
                .type(SnapType.STRING)
                .required()
                .obfuscate()
                .add();
        propertyBuilder
                .describe(IV_PROP, CRYPTO_IV_LABEL, CRYPTO_IV_DESC)
                .type(SnapType.STRING)
                .add();
    }

    @Override
    public void configure(PropertyValues propertyValues) throws ConfigurationException {
        setAlgorithmSpecificValues(propertyValues);

        //get user name and password from the account
        username = account.getUsername();
        password = account.getPassword();
        
        secretKeyName = propertyValues.get(SECRET_KEY_PROP);
        initializationVector = propertyValues.get(IV_PROP);
        // If not Initialization vector is not used with any mode, add if condition for that mode
        if (!cipherMode.equals(ECB_MODE) && StringUtils.isNotBlank(initializationVector)) {
            ivParameterSpec = createIVParameterSpec(initializationVector);
        }

        try {
            transformation = String.format("%s/%s/%s", cryptoAlgorithm, cipherMode, cryptoPadding);
            LOGGER.debug("Configured transformation:"+transformation);
            java.security.Security.addProvider(new IngrianProvider());
            cipher = Cipher.getInstance(transformation,"IngrianProvider");
            LOGGER.debug("Configured cipher:"+transformation);
        } catch (NoSuchAlgorithmException e) {
            throw new ConfigurationException(e, NO_SUCH_ALGORITHM)
                    .formatWith(transformation)
                    .withReason(NO_SUCH_ALGORITHM)
                    .withResolutionAsDefect();
        } catch (NoSuchPaddingException e) {
            throw new ConfigurationException(e, NO_SUCH_PADDING)
                    .formatWith(cryptoPadding)
                    .withReason(NO_SUCH_PADDING)
                    .withResolutionAsDefect();
        } catch (NoSuchProviderException e) {
        	 throw new ConfigurationException(e, SAFENET_ERR_PLEASE_CHECK_PROVIDER)
             .withReason(SAFENET_ERR_PLEASE_CHECK_PROVIDER_REASON)
             .withResolutionAsDefect();	
        }
    }

    /**
     *
     * @param initializationVector initialization vector string
     * @param password string used to generate secret key
     * @return IV parameter specification
     */
    private IvParameterSpec createIVParameterSpec(String initializationVector/*, String password*/) {
        IvParameterSpec ivParameterSpec = null;
        if (StringUtils.isNotBlank(initializationVector)) {
            try {
                byte[] ivParameterBytes = new BigInteger(initializationVector, HEX_RADIX)
                        .toByteArray();
                ivParameterSpec = new IvParameterSpec(ivParameterBytes);
            } catch (NumberFormatException e) {
                throw new ConfigurationException(e, INVALID_ALGORITHM_PARAMETER)
                        .withReason(INVALID_ALGORITHM_PARAMETER)
                        .withResolution(PLEASE_CHECK_IV);
            }
        }
        return ivParameterSpec;
    }


    /**
     * Initialize algorithm-specific properties
     *
     * @param propertyValues Property values configured for this snap execution
     */
    protected abstract void setAlgorithmSpecificValues(PropertyValues propertyValues);

    @Override
    protected void process(final Document header, final ReadableByteChannel readChannel) {
    	
        outputViews.write(new BinaryOutput() {
            @Override
            public Document getHeader() {
                return header;
            }

            @Override
            public void write(WritableByteChannel writeChannel) throws IOException {
        		
        		  try (InputStream inputStream = Channels.newInputStream(readChannel);
                        OutputStream outputStream = Channels.newOutputStream(writeChannel)) {
        			  
					session = NAESession.getSession(username, password.toCharArray());
					secretKey = NAEKey.getSecretKey(secretKeyName, session);
                	
                    if (ivParameterSpec == null) {
                        cipher.init(cryptoMode, secretKey);
                    } else {
                        cipher.init(cryptoMode, secretKey, ivParameterSpec);
                    }
                    
                    byte[] inputstreamBytes = IOUtils.toByteArray(inputStream);
                    byte[] encryptedDecryptedBytes = cipher.doFinal(inputstreamBytes);
                    LOGGER.debug("EncryptedBytes:"+encryptedDecryptedBytes);
                    outputStream.write(encryptedDecryptedBytes);
                } catch (IOException e) {
                	 SnapException snapEx = new SnapDataException(
                              e.getMessage())
                             .withReason(ERROR_PROCESSING_DATA)
                             .withResolutionAsDefect();
                     errorViews.write((SnapDataException) snapEx);
                } catch (InvalidKeyException e) {
                	 SnapException snapEx = new SnapDataException(
                              e.getMessage())
                             .withReason(INVALID_SECRET_KEY)
                             .withResolution(PLEASE_CHECK_SECRET_KEY);
                	 errorViews.write((SnapDataException) snapEx);
                } catch (InvalidAlgorithmParameterException e) {
                	SnapDataException snapEx = new SnapDataException(
                            e.getMessage())
                            .withReason(INVALID_ALGORITHM_PARAMETER)
                            .withResolution(PLEASE_CHECK_IV);
                    errorViews.write(snapEx);
                } catch (IllegalBlockSizeException e) {
                	SnapException snapEx = new SnapDataException(
                             e.getMessage())
                            .withReason(ILLEGAL_BLOCK_SIZE_PARAMETER)
                            .withResolution(PLEASE_CHECK_BLOCK_SIZE);
                	 errorViews.write((SnapDataException) snapEx);
				} catch (BadPaddingException e) {
					SnapException snapEx = new SnapDataException(
                             e.getMessage())
                            .withReason(BAD_PADDING_PARAMETER)
                            .withResolution(PLEASE_CHECK_PADDING);
					 errorViews.write((SnapDataException) snapEx);
				}catch (NAEException e) {
					SnapException snapEx = new SnapDataException(
                            e.getMessage())
                            .withReason(NAE_EXCEPTION_PARAMETER);
					 errorViews.write((SnapDataException) snapEx);
				} finally{
					
				}
            }
        });
    }

    @Override
    public void cleanup() throws ExecutionException {
    	secretKey = null;
		if(session!=null){
			session.closeSession();
		}
    }
}
