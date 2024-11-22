package com.xpanse.los.los_aws_cognito_authorizer;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import com.auth0.jwt.interfaces.RSAKeyProvider;

/** Unit Test Class AwsCognitoRSAKeyProviderTest */
public class AwsCognitoRSAKeyProviderTest {

	/** Unit Test Method getPublicKeyById */
	@Test
	public void getPublicKeyByIdTest() {
		final RSAKeyProvider keyProvider;
		try {
			keyProvider = new AwsCognitoRSAKeyProvider("us-east-1", "us-east-1_56oNxUqcd");
			assertNotNull("key provider is  null",
					keyProvider.getPublicKeyById("5nGV2oyexCb9e4zon6NEhPeJZMrRdtLWEkXWWWgVm+4="));

		} catch (URLException e) {
			e.printStackTrace();
		}

	}

	/** Unit Test Method getPrivateKeyById */
	@Test
	public void getPrivateKeyByIdTest() {
		final RSAKeyProvider keyPrdPrivate;
		try {
			keyPrdPrivate = new AwsCognitoRSAKeyProvider("us-east-1", "us-east-1_56oNxUqcd");
			assertNull("Private Key Id is null", keyPrdPrivate.getPrivateKeyId());

		} catch (URLException e) {
			e.printStackTrace();
		}

	}

	/** Unit Test Method getPrivateKey */
	@Test
	public void getPrivateKeyTest() {
		final RSAKeyProvider keyPrdv;
		try {
			keyPrdv = new AwsCognitoRSAKeyProvider("us-east-1", "us-east-1_56oNxUqcd");
			assertNull("Private Key is  present", keyPrdv.getPrivateKeyId());

		} catch (URLException e) {
			e.printStackTrace();
		}

	}

}
