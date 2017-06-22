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

import org.apache.commons.codec.binary.Base64;

import static demo.Utils.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Rob Winch
 */
public class Main {

	public static void main(String[] args) throws Exception {
		Server server = new Server();

		// we login as "winch"
		String userCookie = server.login("winch", "secret");
		String user = server.getUsername(userCookie);

		System.out.println("Logged in as " + user);

		// Let's hack it to say we are an admin
		// we know the format of the cookie and we know the data of the user we logged in as
		String winchPlainTextFirstBlock = "username=winch&f";
		// we want to be logged in as "admin"
		String adminPlainTextFirstBlock = "username=admin&f";
		// To hack it we need to calculate
		// iv xor originalPlainText xor desiredPlainText
		byte[] originalIv = extractIv(userCookie);
		byte[] xorIvAndOriginalPlainText = xor(originalIv, winchPlainTextFirstBlock.getBytes());
		byte[] adminIv = xor(xorIvAndOriginalPlainText, adminPlainTextFirstBlock.getBytes());

		// now use the newly calculated adminIv with the originalEncryptedText
		byte[] originalEncryptedText = extractMessage(userCookie);
		String adminCookie = createEncryptedCookie(adminIv, originalEncryptedText);

		// See the hacked username
		String admin = server.getUsername(adminCookie);
		System.out.println("Hacked in as " + admin);
	}
}
