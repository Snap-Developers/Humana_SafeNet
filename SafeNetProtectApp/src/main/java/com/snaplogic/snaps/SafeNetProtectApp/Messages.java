/*
 * SnapLogic - Data Integration
 *
 * Copyright (C) 2012 - 2013, SnapLogic, Inc.  All rights reserved.
 *
 * This program is licensed under the terms of
 * the SnapLogic Commercial Subscription agreement.
 *
 * "SnapLogic" is a trademark of SnapLogic, Inc.
 */
package com.snaplogic.snaps.SafeNetProtectApp;

/**
 * Messages is the container for all the externalized messages in this package.
 * Responsibility: Holds externalized messages.
 *
 * @author sprasad
 */
@SuppressWarnings("nls")
class Messages {
    static final String USERNAME_LABEL = "Username";
    static final String USERNAME_DESC = "Username for SSH authentication";
    static final String PASSPHRASE_DESC = "Passphrase used to decrypt the private key.";
    static final String SECRET_KEY_LABEL = "Secret key";
    static final String SECRET_KEY_DESC = "Secret key part of AWS authentication";
    static final String SYMMETRIC_SECRET_KEY_DESC = "Symmetric secret key for authentication";
    static final String CRYPTO_PASSWORD_LABEL = "Password";
    static final String CRYPTO_PASSWORD_DESC = "Password";
    static final String CRYPTO_USERNAME_LABEL = "Username";
    static final String CRYPTO_USERNAME_DESC = "User Name";
    static final String CRYPTO_SECRET_KEY_LABEL = "Secret key name";
    static final String CRYPTO_SECRET_KEY_DESC = "Secret key name for encryption.";
    static final String CRYPTO_IV_LABEL = "Initialization vector";
    static final String CRYPTO_IV_DESC = "Initialization vector for encryption. Should be in " +
            "hexadecimal form. Not used in ECB mode. For advanced users.";
    static final String CRYPTO_CIPHER_MODE_LABEL = "Cipher mode";
    static final String CRYPTO_CIPHER_MODE_DESC = "Cipher mode for encryption";
    static final String CRYPTO_PADDING_LABEL = "Encryption padding";
    static final String CRYPTO_PADDING_DESC = "Encryption padding";
    static final String NO_SUCH_ALGORITHM = "Encryption algorithm not found: %s.";
    static final String NO_SUCH_PADDING = "Padding not found for %s.";
    static final String ERROR_PROCESSING_DATA = "Error processing data.";
    static final String INVALID_SECRET_KEY = "Invalid secret key";
    static final String PLEASE_CHECK_SECRET_KEY = "Please provide a valid secret key.";
    static final String NAE_EXCEPTION_PARAMETER = "NAE Exception.";
    static final String ILLEGAL_BLOCK_SIZE_PARAMETER = "Illegal cipher block size.";
    static final String PLEASE_CHECK_BLOCK_SIZE = "Please check the block size for the given text. Or try with Padding";
    static final String BAD_PADDING_PARAMETER = "Bad padding method.";
    static final String PLEASE_CHECK_PADDING = "Please check the padding method.";
    static final String INVALID_ALGORITHM_PARAMETER = "Invalid algorithm parameter.";
    static final String PLEASE_CHECK_IV = "Please check your initialization vector.";
    static final String SAFENET_AES_ENCRYPT_LABEL = "Safenet AES Encrypt";
    static final String SAFENET_AES_ENCRYPT_DESC = "Encrypt the contents of a binary stream using the Safenet AES" +
            " algorithm.";
    static final String SAFENET_AES_DECRYPT_LABEL = "Safenet AES Decrypt";
    static final String SAFENET_AES_DECRYPT_DESC = "Decrypt the contents of a binary stream using the Safenet AES" +
            " algorithm.";
    static final String FILE_CANNOT_BE_RUN_ON_YARN = "File: %s cannot be run on YARN";
    static final String SAFENET_SYMMETRIC_KEY_ACCOUNT_TITLE = "Safenet Symmetric crypto account";
    static final String CRYPTO_ALGORITHM_LABEL = "Encryption algorithm";
    static final String CRYPTO_ALGORITHM_DESC = "Algorithm used for encryption";
    static final String ERR_VALIDATE_ACCOUNT = "Failed to validate account,";
    static final String ERR_VALIDATE_ACCOUNT_RESOLUTION = "Please ensure that the username and "
            + "password are valid";
    static final String SAFENET_ERR_PLEASE_CHECK_PROVIDER = "Invalid Ingrian provider";
    static final String SAFENET_ERR_PLEASE_CHECK_PROVIDER_REASON = "Provider name couldn't be resolved";
    static final String SAFENET_ERR_PLEASE_CHECK_PROVIDER_RESOLUTION = "Please check provider settings"
            + " in your security configuration";
}
