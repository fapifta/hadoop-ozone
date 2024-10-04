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
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Certificate storage for reading in trusted certificates.
 */
public class TrustedCertStorage extends CertificateStorage {

  private static final Logger LOG =
      LoggerFactory.getLogger(TrustedCertStorage.class);

  public TrustedCertStorage(SecurityConfig securityConfig, String componentName) {
    super(securityConfig, componentName);
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  public KeyStore getKeyStore() throws IOException {
    try {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
      getCertificates().forEach(certPath -> insertCertsToKeystore(keyStore, certPath));
      return keyStore;
    } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
      throw new IOException("Error while creating keystore", e);
    }
  }

  private void insertCertsToKeystore(KeyStore keyStore, CertPath certPath) {
    X509Certificate cert = (X509Certificate) certPath.getCertificates().get(0);
    try {
      keyStore.setCertificateEntry(cert.getSerialNumber().toString(), cert);
    } catch (KeyStoreException ignored) {
    }
  }

  @Override
  public List<CertPath> getCertificates() {
    Path certificateLocation = getSecurityConfig().getCertificateLocation(getComponentName());
    if (!certificateLocation.toFile().exists()) {
      throw new RuntimeException("Certificate location doesn't exist: " + certificateLocation);
    }
    try (Stream<Path> certFiles = Files.list(certificateLocation)) {
      return certFiles
          .filter(Files::isRegularFile)
          .filter(this::isCaCertPath)
          .map(this::readCertFile)
          .collect(Collectors.toList());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private boolean isCaCertPath(Path path) {
    return path.getFileName().toString().startsWith(CAType.ROOT.getFileNamePrefix()) ||
        path.getFileName().toString().startsWith(CAType.SUBORDINATE.getFileNamePrefix());
  }
}
