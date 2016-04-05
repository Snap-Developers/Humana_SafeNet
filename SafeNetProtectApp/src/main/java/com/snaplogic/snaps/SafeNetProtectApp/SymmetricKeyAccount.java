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

import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.NAESession;
import com.snaplogic.account.api.AccountType;
import com.snaplogic.account.api.ValidatableAccount;
import com.snaplogic.account.api.capabilities.AccountCategory;
import com.snaplogic.api.ExecutionException;
import com.snaplogic.common.SnapType;
import com.snaplogic.common.properties.builders.PropertyBuilder;
import com.snaplogic.snap.api.PropertyValues;
import com.snaplogic.snap.api.capabilities.General;
import com.snaplogic.snap.api.capabilities.Version;
import com.snaplogic.snaps.SafeNetProtectApp.AbstractSymmetricCryptoSnap.CryptoAlgorithm;

import java.util.EnumSet;
import java.util.Set;

import static com.snaplogic.snaps.SafeNetProtectApp.Messages.*;

/**
 * Represent a symmetric key account.
 *
 * @author sprasad
 */
@General(title = SAFENET_SYMMETRIC_KEY_ACCOUNT_TITLE)
@Version(snap = 1)
@AccountCategory(type = AccountType.CUSTOM)
public class SymmetricKeyAccount implements ValidatableAccount<String> {
	private static final String PASSWORD_PROP = "password";
	private static final String USERNAME_PROP = "username";
    static final String CRYPTO_ALGORITHM_PROP = "cryptoAlgorithm";
    protected String username;
    protected String password;

    private static final Set<CryptoAlgorithm> ALLOWED_TYPES = EnumSet.allOf(CryptoAlgorithm.class);

    @Override
    public void defineProperties(final PropertyBuilder propertyBuilder) {
		propertyBuilder
				.describe(USERNAME_PROP, CRYPTO_USERNAME_LABEL,
						CRYPTO_USERNAME_DESC).type(SnapType.STRING)
						.required()
				.add();
		propertyBuilder
		.describe(PASSWORD_PROP, CRYPTO_PASSWORD_LABEL,
				CRYPTO_PASSWORD_DESC).type(SnapType.STRING).obfuscate()
				.required()
		.add();
        propertyBuilder
                .describe(CRYPTO_ALGORITHM_PROP, CRYPTO_ALGORITHM_LABEL, CRYPTO_ALGORITHM_DESC)
                .type(SnapType.STRING)
                .withAllowedValues(ALLOWED_TYPES)
                .defaultValue(CryptoAlgorithm.AES.getName())
                .required()
                .add();
    }

    @Override
    public void configure(final PropertyValues propertyValues) {
        username = propertyValues.get(USERNAME_PROP);
        password = propertyValues.get(PASSWORD_PROP);
    }

    @Override
    public String connect() throws ExecutionException {
    	NAESession session=null;
    	try{
    		java.security.Security.addProvider(new IngrianProvider());
        	session = NAESession.getSession(username, password.toCharArray());
    	}catch(Exception e){
            throw new ExecutionException(e, ERR_VALIDATE_ACCOUNT)
                    .withReason(e.getMessage());
    	} finally{
    		if(session!=null){
    			session.closeSession();	
    		}
    	}
        return "";
    }

    @Override
    public void disconnect() throws ExecutionException {
        // NO OP
    }
    
    public String getUsername(){
    	return username;
    }
    public String getPassword(){
    	return password;
    }
}