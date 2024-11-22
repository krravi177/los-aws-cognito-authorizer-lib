package com.xpanse.los.los_aws_cognito_authorizer;

/** Custom URL Excpetion Class */
public class URLException extends Exception {
	/**
	 * default serialVersionUID field
	 */
	private static final long serialVersionUID = 7L;

	/** constructor */
	public URLException(final String errorMessage) {
		super(errorMessage);
	}
}
