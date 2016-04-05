package com.snaplogic.snaps.SafeNetProtectApp;
/**
 * SnapLogic - Data Integration
 *
 * Copyright (C) 2013, SnapLogic, Inc.  All rights reserved.
 *
 * This program is licensed under the terms of
 * the SnapLogic Commercial Subscription agreement.
 *
 * "SnapLogic" is a trademark of SnapLogic, Inc.
 * 
 *  @author sprasad
 **/

import com.snaplogic.common.SnapType;
import com.snaplogic.common.properties.builders.PropertyBuilder;
import com.snaplogic.snap.api.PropertyValues;
import com.snaplogic.snap.api.capabilities.Category;
import com.snaplogic.snap.api.SnapCategory;
import com.snaplogic.snap.api.capabilities.General;
import com.snaplogic.snap.api.capabilities.Version;

import java.util.EnumSet;
import java.util.Set;

import javax.crypto.Cipher;

import static com.snaplogic.snaps.SafeNetProtectApp.Messages.SAFENET_AES_ENCRYPT_DESC;
import static com.snaplogic.snaps.SafeNetProtectApp.Messages.SAFENET_AES_ENCRYPT_LABEL;
import static com.snaplogic.snaps.SafeNetProtectApp.Messages.CRYPTO_CIPHER_MODE_DESC;
import static com.snaplogic.snaps.SafeNetProtectApp.Messages.CRYPTO_CIPHER_MODE_LABEL;
import static com.snaplogic.snaps.SafeNetProtectApp.Messages.CRYPTO_PADDING_DESC;
import static com.snaplogic.snaps.SafeNetProtectApp.Messages.CRYPTO_PADDING_LABEL;

/**
 * The AES Encrypt snap encrypts the binary documents it receives on its input view using the
 * user-specified encryption parameters.
 *
 * <p>
 * The snap uses the following properties:
 * <ul>
 * <li>Secret key - secret encryption/decryption key</li>
 * <li>Initialization vector - an arbitrary number that can be used along with a secret key for data
 * encryption</li>
 * <li>Cipher mode - mode of operation for a block cipher</li>
 * <li>Padding - padding scheme for a block cipher</li>
 * </ul>
 *
 * @author sprasad
 */
@General(title = SAFENET_AES_ENCRYPT_LABEL, purpose = SAFENET_AES_ENCRYPT_DESC)
@Category(snap = SnapCategory.WRITE)
@Version(snap = 1)
public class AESEncrypt extends AbstractSymmetricCryptoSnap {
    private static final Set<AESCipherMode> ALLOWED_MODES = EnumSet.allOf(AESCipherMode.class);
    private static final Set<CryptoPadding> ALLOWED_PADDINGS = EnumSet.allOf(CryptoPadding.class);

    @Override
    public void defineProperties(PropertyBuilder propertyBuilder) {
        super.defineProperties(propertyBuilder);
        propertyBuilder.describe(CIPHER_MODE_PROP, CRYPTO_CIPHER_MODE_LABEL,
                CRYPTO_CIPHER_MODE_DESC)
                .type(SnapType.STRING)
                .withAllowedValues(ALLOWED_MODES)
                .defaultValue(AESCipherMode.ECB.toString())
                .add();
        propertyBuilder.describe(PADDING_PROP, CRYPTO_PADDING_LABEL, CRYPTO_PADDING_DESC)
                .type(SnapType.STRING)
                .withAllowedValues(ALLOWED_PADDINGS)
                .defaultValue(CryptoPadding.PKCS5PADDING.toString())
                .add();
    }

    @Override
    protected void setAlgorithmSpecificValues(PropertyValues propertyValues) {
        cryptoAlgorithm = CryptoAlgorithm.AES.getName();
        cryptoMode = Cipher.ENCRYPT_MODE;
        cipherMode = AESCipherMode.valueOf((String) propertyValues.get(CIPHER_MODE_PROP))
                .toString();
        cryptoPadding = CryptoPadding.valueOf((String) propertyValues.get(PADDING_PROP)).toString();
    }
}
