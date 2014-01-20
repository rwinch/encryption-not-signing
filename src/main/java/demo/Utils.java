package demo;/*
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

import org.apache.commons.codec.binary.Base64;

/**
 * @author Rob Winch
 */
class Utils {

	/**
	 * Since encryptedCookie is IV + encrypted we can grab the first 16 bytes as the IV (IV of AES is 16)
	 * @param encryptedCookie
	 * @return
	 */
	static byte[] extractIv(String encryptedCookie) {
		byte[] iv = new byte[16]; // IV of AES is 16
		System.arraycopy(Base64.decodeBase64(encryptedCookie), 0, iv, 0, iv.length);
		return iv;
	}

	/**
	 * Since encryptedCookie is IV + encrypted we can grab the bytes after the IV (IV of AES is 16) to get the encrypted value
	 * @param encryptedCookie
	 * @return
	 */
	static byte[] extractMessage(String encryptedCookie) {
		byte[] message = Base64.decodeBase64(encryptedCookie);
		byte[] encryptedMessageBytes = new byte[message.length - 16];
		System.arraycopy(message, 16, encryptedMessageBytes, 0, encryptedMessageBytes.length);
		return encryptedMessageBytes;
	}

	static byte[] xor(byte[] a, byte[] b) {
		byte[] result = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			result[i] = (byte) (a[i] ^ b[i]);
		}
		return result;
	}


	/**
	 * Merges the IV and the enctyped text and returns it base 64 encoded
	 * @param iv
	 * @param encrypted
	 * @return
	 */
	static String createEncryptedCookie(byte[] iv, byte[] encrypted) {
		byte[] result = new byte[iv.length + encrypted.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
		return Base64.encodeBase64String(result);
	}

	private Utils() {}
}
