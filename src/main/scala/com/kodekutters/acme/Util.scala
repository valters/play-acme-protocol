/*
 * Copyright 2015 Ringo Wathelet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kodekutters

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import javax.security.cert.X509Certificate

/**
 * utilities supporting the ACME protocol
 *
 * Reference: Let's Encrypt project at: https://letsencrypt.org/
 */
package object Util {

  /**
   * test if the current running java is at least version n.
   * @param n the string representing the java version number to test (e.g. "1.8")
   * @return true if n >= the current running java version, false for anything else.
   */
  def isJavaAtLeast(n: String): Boolean = {
    try {
      n.toFloat >= System.getProperty("java.version").substring(0, 3).toFloat
    }
    catch {
      case e: Exception => false
    }
  }

  /**
   * pad the input string with "=" and "=="
   * @param x the input string to pad
   * @return the input string padded with "=" and "=="
   */
  def pad(x: String): String = {
    x.length % 4 match {
      case 2 => x + "=="
      case 3 => x + "="
      case _ => x
    }
  }

  /**
   * remove any "=" from the input string
   * @param x the imput string
   * @return the input string with all "=" removed
   */
  def unpad(x: String): String = x.replace("=", "")

  /**
   * create a base64 encoded string from the input bytes
   * @param x input byte array to encode
   * @return a base64 encoded string
   */
  def base64Encode(x: Array[Byte]): String = unpad(Base64.getUrlEncoder.encodeToString(x))

  /**
   * decode a base64 encoded string into a byte array
   * @param x the input string
   * @return the decoded string as a byte array
   */
  def base64Decode(x: String): Array[Byte] = Base64.getUrlDecoder.decode(pad(x))

  /**
   * create a n bytes random number base 64 encoded string
   * @param n number of bytes
   * @return a n bytes random number base 64 encoded string
   */
  def randomString(n: Int): String = {
    require(n > 0, "Util package, randomString(n) should have n > 0")
    val b = new Array[Byte](n)
    SecureRandom.getInstanceStrong.nextBytes(b)
    Base64.getEncoder.encodeToString(b)
  }

  /**
   * create a new 64 bit random number
   * @return a BigInteger, a 64 bit random number
   */
  def new64BitRandom: BigInteger = new BigInteger(64, SecureRandom.getInstanceStrong)

  /**
   * create a nonce as a 16 bytes random number base 64 encoded string
   * @return 16 bytes random number base 64 encoded string
   */
  def newNonce: String = randomString(16)

  /**
   * convenience method, creates a option nonce as a 16 bytes random number base 64 encoded string
   * @return 16 bytes random number base 64 encoded option string
   */
  def newNonceOpt: Option[String] = Some(newNonce)

  /**
   * create a new random 32 bytes base 64 encoded string
   * @return
   */
  def newToken: String = randomString(32)

  /**
   * create a PEM representation of the input X509Certificate
   * @param certificate the input X509Certificate
   * @return a PEM string of the input X509Certificate
   */
  def toPEM(certificate: X509Certificate): String = {
    val derCert = certificate.getEncoded()
    val pemCertPre = new String(Base64.getEncoder.encode(derCert), "UTF-8")
    "-----BEGIN CERTIFICATE-----\n" + pemCertPre + "-----END CERTIFICATE-----"
  }

}
