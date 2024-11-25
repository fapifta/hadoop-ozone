/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.hadoop.hdds.security.x509.certificate.client;

import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.exception.OzoneSecurityException;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;

import java.io.Closeable;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * Certificate client provides and interface to certificate operations that
 * needs to be performed by all clients in the Ozone eco-system.
 */
public interface CertificateClient extends Closeable {

  /**
   * Return component name of this certificate client.
   *
   * @return component name
   */
  String getComponentName();

  SecurityConfig getSecurityConfig();

  /**
   * Returns the certificate used by the specified component if it exists
   * on the local system.
   *
   * @return the target certificate or null if there is no data.
   */
  X509Certificate getCertificate();

  String getCertSerialId();

  /**
   * Verifies a digital Signature, given the signature and the certificate of
   * the signer.
   *
   * @param data      - Data in byte array.
   * @param signature - Byte Array containing the signature.
   * @param cert      - Certificate of the Signer.
   * @return true if verified, false if not.
   */
  boolean verifySignature(byte[] data, byte[] signature,
      X509Certificate cert) throws CertificateException;

  String signCertificate(CertificateSignRequest csr) throws CertificateException;

  List<String> getAllRootCaCertificates() throws IOException;

  /**
   * Returns a CertificateSignRequest Builder object, that can be used to configure the sign request
   * which we use to get  a signed certificate from our CA server implementation.
   *
   * @return CertificateSignRequest.Builder a {@link CertificateSignRequest}
   * based on which the certificate may be issued to this client.
   */
  CertificateSignRequest.Builder configureCSRBuilder() throws SCMSecurityException;

  void assertValidKeysAndCertificate() throws OzoneSecurityException;

  /**
   * Register a receiver that will be called after the certificate renewed.
   *
   * @param receiver
   */
  void registerNotificationReceiver(CertificateNotification receiver);

  /**
   * Registers a listener that will be notified if the CA certificates are
   * changed.
   *
   * @param listener the listener to call with the actualized list of CA
   *                 certificates.
   */
  void registerRootCARotationListener(
      Function<List<X509Certificate>, CompletableFuture<Void>> listener);

  /**
   * Initialize certificate client.
   *
   * */
  void initWithRecovery() throws IOException;

  /**
   * Represents initialization response of client.
   * 1. SUCCESS: Means client is initialized successfully and all required
   *              files are in expected state.
   * 2. FAILURE: Initialization failed due to some unrecoverable error.
   * 3. GETCERT: Bootstrap of keypair is successful but certificate is not
   *             found. Client should request SCM signed certificate.
   *
   */
  enum InitResponse {
    SUCCESS,
    FAILURE,
    GETCERT
  }
}
