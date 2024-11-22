package com.xpanse.los.los_aws_cognito_authorizer;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

/** AWS Cognito Token Verification class */
public class AwsCognitoTokenVerification {
	/** logger object */
	private static final Logger logger = LogManager.getLogger(AwsCognitoTokenVerification.class);

	/** verify congnito JWT token method */
	public Map<String, Object> verifyToken(final String token, final String awsCognitoRegion,
			final String awsUserPoolsId) {

		final Map<String, Object> responseMap = new ConcurrentHashMap<>();

		try {

			final RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(awsCognitoRegion, awsUserPoolsId);
			final Algorithm algorithm = Algorithm.RSA256(keyProvider);
			final JWTVerifier jwtVerifier = JWT.require(algorithm).build();

			final DecodedJWT decodedJwt = jwtVerifier.verify(token);

			// Fails if the token is not valid
			if (decodedJwt == null) {
				responseMap.put(AppConstants.RESPONSE_CODE, "400");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "Malformed token");
				responseMap.put(AppConstants.RESPONSE_DATA, "Error : Malformed token");

			} else if (isJWTExpired(decodedJwt)) {
				responseMap.put(AppConstants.RESPONSE_CODE, "401");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "Token Expired");
				responseMap.put(AppConstants.RESPONSE_DATA, "Error : Token Expired");

			} else {
				responseMap.put(AppConstants.RESPONSE_CODE, "200");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "Success");
				responseMap.put(AppConstants.RESPONSE_DATA, "Token verified");

			}

		} catch (Exception e) {
			logger.error("los-aws-cognito-authorizer-lib | AwsCognitoTokenVerification - verifyToken [ERROR]  ", e);

			if (e.getMessage().contains("Token has expired")) {
				responseMap.put(AppConstants.RESPONSE_CODE, "401");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "Token Expired");
				responseMap.put(AppConstants.RESPONSE_DATA, "Error :" + e.getMessage());
			} else if (e.getMessage().contains("doesn't have a valid JSON format.")) {
				responseMap.put(AppConstants.RESPONSE_CODE, "400");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "Malformed token");
				responseMap.put(AppConstants.RESPONSE_DATA, "Error :   " + e.getMessage());

			} else {
				responseMap.put(AppConstants.RESPONSE_CODE, "409");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "Error occured while verifying token");
				responseMap.put(AppConstants.RESPONSE_DATA, "Error:  " + e.getMessage());

			}

		}
		return responseMap;
	}

	/** check jwt token expire method */
	private boolean isJWTExpired(final DecodedJWT decodedJWT) {
		final Date expiresAt = decodedJWT.getExpiresAt();
		return expiresAt.before(new Date());
	}
	
	

}
