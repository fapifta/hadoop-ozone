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

package org.apache.hadoop.hdds.security.x509.certificate.utils;

import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.ssl.ReloadingX509TrustManager;
import org.apache.hadoop.hdds.security.x509.certificate.client.CertificateNotification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Certificate storage for reading in trusted certificates.
 */
public class TrustedCertStorage extends CertificateStorage implements CertificateNotification {

  private static final Logger LOG =
      LoggerFactory.getLogger(TrustedCertStorage.class);
  private ReloadingX509TrustManager trustManager;

  public TrustedCertStorage(SecurityConfig securityConfig, String componentName) {
    super(securityConfig, componentName);
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  /**
   * Returns true for self-signed certificates.
   *
   * @return true if the certificate is self-signed, false otherwise
   */
  @Override
  public Predicate<CertPath> getCertificateFilter() {
    return certPath -> isSelfSignedCertificate((X509Certificate) certPath.getCertificates().get(0));
  }

  public X509Certificate getLatestRootCaCert() {
    Set<X509Certificate> leafCertificates = getLeafCertificates();
    if (leafCertificates.isEmpty()) {
      LOG.error("Failed to find any non null RootCACertificates");
      return null;
    }
    return leafCertificates.stream()
        .max(Comparator.comparing(X509Certificate::getSerialNumber))
        .orElse(null);
  }

  private static boolean isSelfSignedCertificate(X509Certificate cert) {
    return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
  }

  @Override
  public void notifyCertificateRenewed(String oldCertId, String newCertId) {
    trustManager.notifyCertificateRenewed(oldCertId, newCertId);
  }

  public synchronized ReloadingX509TrustManager getTrustManager() throws
      org.apache.hadoop.hdds.security.x509.exception.CertificateException {
    try {
      if (trustManager == null) {
        trustManager = new ReloadingX509TrustManager(KeyStore.getDefaultType(), this);
      }
      return trustManager;
    } catch (IOException | GeneralSecurityException e) {
      throw new org.apache.hadoop.hdds.security.x509.exception.CertificateException("Failed to init trustManager", e,
          org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.KEYSTORE_ERROR);
    }
  }
}
