# Exploiting encrypted cookies for fun and profit

This is a sample project and text for a [blog post](http://spring.io/blog/2014/01/20/exploiting-encrypted-cookies-for-fun-and-profit) found on spring.io.

## Introduction

Developers often incorrectly use encryption in an attempt to provide authenticity. For example, a RESTful application may mistakenly use an encrypted cookie to embed the current user's identity.

The mistake is that encryption can only be used to keep a secret while signing is used to verify authenticity of a message. In this post, I will explain and provide an example of why encryption is not a guarantee of authenticity.

If you just want to see code, feel free to skip [to the end](#source-code) which has a sample Java application that demonstrates the exploit.

## Encrypted Cookies (whoops)

Assume we want to avoid looking up our users in session and instead want to embed the user information within a cookie. Since cookies can be modified by a malicious user we will need to be able to verify that the cookie that was provided was created by our application server.

To prevent users from tampering with the cookies we _mistakenly_ decide to encrypt the cookie using [AES encryption](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with [CBC mode](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29) instead of signing the cookie. Our cookie is properly encrypted (but mistakenly not signed) as follows:

```text
Cookie = Base64String( IV, aes_cbc(k, IV, plainText) )
```

Such that:

* __Base64String__ - concatenates each byte[] and then returns the Base64 String of the concatenated byte[]
* __k__ - is a secret key that is only known to our server
* __IV__ - is a randomly generated [Initialization Vector](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_.28IV.29) 
* __aes_cbc__ - encrypts the plainText using AES/CBC with the provided IV 
* __plainText__ - is in the format of "username=winch&firstName=Rob&lastName=Winch"

__NOTE__: It is safe and common for us to include the IV in plaintext along with the encrypted text. Since the IV is a fixed number of bytes, it can be easily extracted from a combined IV,encrypted_value byte[].

## Review of XOR

Before we go any further it is important to understand [XOR](http://en.wikipedia.org/wiki/Exclusive_or). To refresh your memory here is a truth table for XOR

A   | B   | Output
--- | --- | ---
0   | 0   | 0
0   |  1  | 1
1   |  0  | 1
1   |  1  | 0

## How does CBC decryption use the IV?

To understand how we are going to impersonate another user, we first need to understand a little bit how AES / CBC works. AES is a [block cypher](http://en.wikipedia.org/wiki/Block_cipher) which means our message is broken into fixed size blocks and then operations are performed on each block.

When decrypting AES / CBC, the decrypted value of the first block is XORed with the IV. For example, the following would hold true.

```text
decrypt(k, encrypted_first_block) XOR IV = plaintext_first_block
```

To get a better understanding, let's take a look at a concrete example. Assume that the following is true:

* decrypt(k, encrypted_first_block) is 11011101
* IV is 10101010

__NOTE__: Our example is simplified by using a block size of 8 bits instead of the actual block size of 128 bits. This makes it easier for humans to follow along.

This means our plaintext_first_block would be 01110111 ("w" in [ASCII](http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters)). Our work is shown below:

```text
     decrypt(k, encrypted_first_block)
 XOR IV
 ------------
     plaintext_first_block
 
    11011101       
XOR 10101010
------------
    01110111 // "w" ASCII
```

## Modifying the decrypted value

With the information above, we can modify the decrypted value. Specifically, given:

* a valid encrypted value
* the corresponding IV
* the corresponding plaintext

we can calculate a modified IV named IV' that will be combined with the original valid encrypted value to impersonate another user.
 
The first step is to calculate the unknown value of decrypt(k, encrypted_first_block) by canceling out all the bits in the IV by XOR with the first_block_plaintext. Our work is illustrated below:
   
 ```text
     IV
 XOR plaintext_first_block
 ------------
     decrypt(k, encrypted_first_block)
 
     10101010       
 XOR 01110111
 ------------
     11011101
 ```
 
The final step is to calculate IV' by executing decrypt(k, encrypted_first_block) XOR desired_plaintext_first_block. Once again, our work is illustrated below:
   
 ```text
     decrypt(k, encrypted_first_block)
 XOR desired_plaintext_first_block
 ------------
     IV'
 
     11011101       
 XOR 01100001 // "a" ASCII
 ------------
     10111100
 ```

We can now verify that providing IV' with the originally encrypted value would result in "a" instead of "w". 

```text
     decrypt(k, encrypted_first_block)
 XOR IV'
 ------------
     desired_plaintext_first_block
 
    11011101       
XOR 10111100
------------
    01100001 // This is "a" ASCII
```

This demonstrates that if we provide IV' (instead of IV) along with the originally encrypted value it will be decrypted as "a".

## Impersonating another user

Now that we have seen how we can create a modified IV to make our encrypted value whatever we like, let's explore how this applies to us authenticating as a user and then modifying our encrypted cookie to impersonate another user.

In the [Modifying the decrypted value](#modifying-the-decrypted-value) section, we mentioned we needed some information before we could perform the exploit. Let's see how we can obtain the information necessary for the exploit with the encrypted cookie:

* __a valid encrypted value__ - An encrypted value is transmitted in the cookie and can be viewed by anyone with a valid account
* __the corresponding IV__ - An IV is transmitted in the cookie and can be viewed by anyone with a valid account
* __the corresponding plaintext__ - For simplicity, assume a malicious user discovered the format of the cookie by observing the cookie name corresponded to an open source framework. The format was then calculated by knowledge of the user we authenticated as and studying the code of the open source framework.

Now that we have the necessary information and have an understanding of how we can [modify the encrypted value](#modifying-the-decrypted-value), it is easy to see that we can impersonate any user we want. So long as we have a valid account, we can create an IV' that changes the username in the encrypted cookie to be the desired user of our choice.

## Source Code

Not convinced of the exploit? See it demonstrated by running the [sample project on github](https://github.com/rwinch/encryption-not-signing). To run the sample import it as a Maven project into your favorite IDE and run the [demo.Main](https://github.com/rwinch/encryption-not-signing/blob/master/src/main/java/demo/Main.java) class.

You will observe that we authenticate as "winch" but are able to modify the encrypted cookie to impersonate a user named "admin".

## Conclusion

At this point I hope you are convinced that encryption is not a valid way of providing authenticity. Instead, we would need ensure the cookie is signed. One solution would be to use [authenticated encryption](http://en.wikipedia.org/wiki/Authenticated_encryption) which provides secrecy, integrity, and authenticity.

Please keep in mind that simply signing our cookie does not make it secure. There are other attack vectors, like [replay attacks](http://en.wikipedia.org/wiki/Replay_attack), that must be addressed in order to make the solution secure.

We must realize that security is hard and should not be implemented on your own or even within a small number of individuals. Instead security is best implemented in a community that can check one another for mistakes.
