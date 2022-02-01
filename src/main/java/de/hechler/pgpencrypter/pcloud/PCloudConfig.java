package de.hechler.pgpencrypter.pcloud;

import java.io.FileInputStream;
import java.util.Properties;

import de.hechler.pgpencrypter.utils.SimpleCrypto;

/**
 * Test using pCloud API - Java SDK https://github.com/pCloud/pcloud-sdk-java
 * 
 * SDK docu: https://pcloud.github.io/pcloud-sdk-java/
 * 
 * API docu: https://docs.pcloud.com/
 * 
 * @author feri
 */

public class PCloudConfig {

	private final static String APP_NAME = "PCloudApi";

	private String clientId;
	private String encClientSecret;
	private String encAccessToken;
	private String apiHost;

	public PCloudConfig(String propertiesFile) {
		try {
			Properties envProps = new Properties();
			envProps.load(new FileInputStream(propertiesFile));
			clientId = envProps.getProperty("CLIENT_ID").trim();
			encClientSecret = envProps.getProperty("ENC_CLIENT_SECRET");
			if (encClientSecret == null) {
				encClientSecret = SimpleCrypto.encrypt(APP_NAME + 42, envProps.getProperty("CLIENT_SECRET").trim());
				System.out.println("ENC_CLIENT_SECRET=" + encClientSecret);
			}
			encAccessToken = envProps.getProperty("ENC_ACCESS_TOKEN");
			if (encAccessToken == null) {
				encAccessToken = SimpleCrypto.encrypt(APP_NAME + 42, envProps.getProperty("ACCESS_TOKEN").trim());
				System.out.println("ENC_ACCESS_TOKEN=" + encAccessToken);
			}
			apiHost = envProps.getProperty("API_HOST").trim();
		} catch (Exception e) {
			throw new RuntimeException("error reding config file '" + propertiesFile + "'", e);
		}
	}

	public String getClientId() {
		return clientId;
	}

	public String getClientSecret() {
		return SimpleCrypto.decrypt(APP_NAME + 42, encClientSecret);
	}

	public String getAccessToken() {
		return SimpleCrypto.decrypt(APP_NAME + 42, encAccessToken);
	}

	public String getApiHost() {
		return apiHost;
	}

}
