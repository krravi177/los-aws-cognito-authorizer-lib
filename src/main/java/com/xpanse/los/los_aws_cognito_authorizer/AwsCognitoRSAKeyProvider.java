package com.xpanse.los.los_aws_cognito_authorizer;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** AwsCognitoRSAKeyProvider Java Class */
public class AwsCognitoRSAKeyProvider implements RSAKeyProvider {
	/** logger object */
	private static final Logger logger = LogManager.getLogger(AwsCognitoRSAKeyProvider.class);

	/** URL global variable */
	private final URL storeUrl;
	/** JWK Provider global variable */
	private final JwkProvider jwkProvider;

	/** AWS Cognitor RAS Key Provider Method */
	public AwsCognitoRSAKeyProvider(final String awsCognitoRegion, final String awsUserPoolId) throws URLException {
		final String url = String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
				awsCognitoRegion, awsUserPoolId);
		try {
			storeUrl = new URL(url);
		} catch (MalformedURLException e) {
			logger.error("los-aws-cognito-authorizer-lib | AwsCognitoRSAKeyProvider - constructor [ERROR]  ", e);

			throw new URLException(String.format("Given URL is not valid, URL=%s ", url));
		}
		jwkProvider = new JwkProviderBuilder(storeUrl).build();
	}

	/** Get Public Key By ID Method */
	@Override
	public RSAPublicKey getPublicKeyById(final String kid) {
		RSAPublicKey rsa = null;
		try {
			rsa = (RSAPublicKey) jwkProvider.get(kid).getPublicKey();
		} catch (JwkException e) {
			logger.error("los-aws-cognito-authorizer-lib | AwsCognitoRSAKeyProvider - getPublicKeyById [ERROR]  ", e);
		}
		return rsa;
	}

	/** Get Private Key Method */
	@Override
	public RSAPrivateKey getPrivateKey() {
		return null;
	}

	/** Get Private Key By ID Method */
	@Override
	public String getPrivateKeyId() {
		return null;
	}
}
