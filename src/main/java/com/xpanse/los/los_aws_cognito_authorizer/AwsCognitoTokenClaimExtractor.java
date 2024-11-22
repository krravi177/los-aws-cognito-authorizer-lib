package com.xpanse.los.los_aws_cognito_authorizer;

import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

/** AWS Cognito Token Verification class */
public class AwsCognitoTokenClaimExtractor {
	/** logger object */
	private static final Logger logger = LogManager.getLogger(AwsCognitoTokenClaimExtractor.class);

	/** Cognito get claims method */
	public Map<String, Claim> getClaims(final String token, final String awsCognitoRegion,
			final String awsUserPoolsId) {

		try {
			final RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(awsCognitoRegion, awsUserPoolsId);
			final Algorithm algorithm = Algorithm.RSA256(keyProvider);
			final JWTVerifier jwtVerifier = JWT.require(algorithm).build();

			final DecodedJWT decodedJwt = jwtVerifier.verify(token);
			return decodedJwt.getClaims();

		} catch (Exception e) {
			logger.error("los-aws-cognito-authorizer-lib | AwsCognitoTokenClaimExtractor - getClaims [ERROR]  ", e);
		}
		return null;
	}

}
