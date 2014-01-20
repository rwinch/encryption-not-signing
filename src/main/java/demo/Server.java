/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package demo;

import static demo.Utils.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static demo.Utils.extractIv;
import static demo.Utils.extractMessage;

/**
 * @author Rob Winch
 */
public class Server {

	private SecretKey aesKey = createKey();
	private Map<String,User> userToPassword = createUsernameToUser();

	/**
	 * If a valid username and password are passed in returns an encrypted cookie that represents the user.
	 *
	 * @param username
	 * @param password
	 * @return
	 * @throws GeneralSecurityException
	 */
	public String login(String username, String password) throws GeneralSecurityException {
		User user = userToPassword.get(username);
		if(user != null && !password.equals(user.getPassword())) {
			throw new RuntimeException("Invalid username/password");
		}

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey);

		String originalText = "username=" + username + "&firstName="+user.getFirstName()+"&lastName="+user.getLastName();

		byte[] encrypted = cipher.doFinal(originalText.getBytes());
		byte[] iv = cipher.getIV();
		return createEncryptedCookie(iv, encrypted);
	}

	/**
	 * Given the encryptedCookie will extract out the username from the cookie and return it.
	 *
	 * @param encryptedCookie
	 * @return
	 * @throws GeneralSecurityException
	 */
	public String getUsername(String encryptedCookie) throws GeneralSecurityException {
		byte[] iv = extractIv(encryptedCookie);
		byte[] encryptedMessageBytes = extractMessage(encryptedCookie);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
		String decryptedCookie = new String(cipher.doFinal(encryptedMessageBytes));

		System.out.println("plainText: "+ decryptedCookie);

		int startIndex = decryptedCookie.indexOf("username=") + 9;
		int endIndex = decryptedCookie.indexOf("&", startIndex);
		return decryptedCookie.substring(startIndex, endIndex);
	}

	private SecretKey createKey() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			return keyGen.generateKey();
		} catch(NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private Map<String,User> createUsernameToUser() {
		Map<String, User> usernameToUser = new HashMap<>();
		usernameToUser.put("winch", new User("winch", "secret", "Rob", "Winch"));
		usernameToUser.put("admin", new User("admin", "topsecret", "The", "Admin"));
		return usernameToUser;
	}
}
