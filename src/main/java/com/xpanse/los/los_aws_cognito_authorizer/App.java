package com.xpanse.los.los_aws_cognito_authorizer;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse.PolicyDocument;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse.Statement;

/** Java Class App */
public class App {
	/** logger object */
	private static final Logger logger = LogManager.getLogger(App.class);

	/** Lamdba Function to be used as service */
	public Map<String, Object> handleRequest(final Map<String, Object> input, final Context context) {
		logger.debug("los-aws-cognito-authorizer-lib | Start : {}", context.getAwsRequestId());

		Map<String, Object> responseMap = callVerifyToken(input,context);
		
		logger.debug("los-aws-cognito-authorizer-lib | End : {}", context.getAwsRequestId());

		return responseMap;

	}

	/** Lamdba Function to be used as API Gateway Authorizer */
	public IamPolicyResponse handleAuthorizer(final Map<String, Object> input, final Context context) {
		logger.debug("los-aws-cognito-authorizer-lib | Start : {}", context.getAwsRequestId());

		String effect = "Deny";

		Map<String, Object> responseMap = callVerifyToken(input,context);

		if (AppConstants.SUCCESS_CODE.equals(responseMap.get("responseCode"))) {
			effect = "Allow";
		} else {
			logger.error("los-aws-cognito-authorizer-lib | Unauthorized");
		}

		final Statement statement = Statement.builder().withAction("execute-api:Invoke")
				.withResource(List.of("arn:aws:execute-api:*:*:*")).withEffect(effect).build();
		final PolicyDocument policyDocument = PolicyDocument.builder().withVersion("2012-10-17")
				.withStatement(Collections.singletonList(statement)).build();

		return IamPolicyResponse.builder().withPrincipalId("me").withPolicyDocument(policyDocument)
				.withContext(responseMap).build();
	}
	
	private Map<String, Object> callVerifyToken(final Map<String, Object> input, final Context context) {
		Map<String, Object> responseMap = new ConcurrentHashMap<>();

		try {
			logger.debug("los-aws-cognito-authorizer-lib | callVerifyToken | Start : {}", context.getAwsRequestId());

			final Map<String, String> headers = input.containsKey(AppConstants.HEADERS)
					? (Map<String, String>) input.get(AppConstants.HEADERS)
					: input.containsKey(AppConstants.HEADER) ? (Map<String, String>) input.get(AppConstants.HEADER)
							: input.containsKey(AppConstants.PARAMS)
									? (Map<String, String>) ((Map<String, Object>) input.get(AppConstants.PARAMS))
											.get(AppConstants.HEADER)
									: null;
			String authorization = headers != null && headers.containsKey(AppConstants.AUTHORIZATION)
						? headers.get(AppConstants.AUTHORIZATION)
						: "";
			
			if (authorization != null && authorization.toLowerCase(Locale.US).startsWith("bearer")) {

				final String token = authorization.substring(7);
				responseMap = new AwsCognitoTokenVerification().verifyToken(token, System.getenv("AWS_COGNITO_REGION"),
						System.getenv("AWS_USER_POOL_ID"));
			} else {
				logger.debug("los-aws-cognito-authorizer-lib | No Authorization header found | requestId :{}",
						context.getAwsRequestId());

				responseMap.put(AppConstants.RESPONSE_CODE, "400");
				responseMap.put(AppConstants.RESPONSE_MESSAGE, "No token found in request");
				responseMap.put(AppConstants.RESPONSE_DATA, "Error : No token found");
			}

		} catch (Exception e) {
			logger.error("los-aws-cognito-authorizer-lib | requestId :{} |  ERROR :{}", context.getAwsRequestId(),
					e.toString());

			responseMap.put(AppConstants.RESPONSE_CODE, "409");
			responseMap.put(AppConstants.RESPONSE_MESSAGE, "Error occured while verifying token");
			responseMap.put(AppConstants.RESPONSE_DATA, "Error : Internal server error occured while verifying token");
		}
		logger.debug("los-aws-cognito-authorizer-lib | callVerifyToken | End : {}", context.getAwsRequestId());

		return responseMap;

	}


}
