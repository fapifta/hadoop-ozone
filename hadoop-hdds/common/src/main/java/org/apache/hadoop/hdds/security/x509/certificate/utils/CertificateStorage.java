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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;

/**
 * Abstract base class for performing certificate related IO operations with the filesystem.
 */
public abstract class CertificateStorage {

  private final SecurityConfig securityConfig;
  private final String componentName;
  private final CertificateCodec certificateCodec;

  protected CertificateStorage(SecurityConfig securityConfig, String componentName) {
    this.securityConfig = securityConfig;
    this.componentName = componentName;
    certificateCodec = new CertificateCodec(securityConfig, componentName);
  }

  public final List<CertPath> getCertPaths() {
    Path certificateLocation = getSecurityConfig().getCertificateLocation(getComponentName());
    if (!certificateLocation.toFile().exists()) {
      getLogger().error("CertificateLocation: {} doesn't exist", certificateLocation);
      return new ArrayList<>();
    }
    try (Stream<Path> certFiles = Files.list(certificateLocation)) {
      return certFiles
          .filter(Files::isRegularFile)
          .map(this::readCertFile)
          .filter(getCertificateFilter())
          .collect(Collectors.toList());
    } catch (IOException e) {
      getLogger().error("Error while reading certificates from path: {}", certificateLocation, e);
      return new ArrayList<>();
    }
  }

  public final KeyStore getKeyStore() throws IOException {
    try {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
      getCertPaths().forEach(certPath -> insertCertsToKeystore(keyStore, certPath));
      return keyStore;
    } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
      throw new IOException("Error while creating keystore", e);
    }
  }

  void insertCertsToKeystore(KeyStore keyStore, CertPath certPath) {
    X509Certificate cert = (X509Certificate) certPath.getCertificates().get(0);
    try {
      keyStore.setCertificateEntry(cert.getSerialNumber().toString(), cert);
    } catch (KeyStoreException e) {
      getLogger().info("There was an error while creating the keystore.", e);
    }
  }

  abstract Predicate<CertPath> getCertificateFilter();

  public SecurityConfig getSecurityConfig() {
    return securityConfig;
  }

  public String getComponentName() {
    return componentName;
  }

  public abstract Logger getLogger();

  private CertPath readCertFile(Path filePath) {
    try {
      Path fileName;
      //do this to avoid the findbugs error about possible nullpointer dereference
      if (filePath != null) {
        fileName = filePath.getFileName();
        if (fileName != null) {
          return certificateCodec.getCertPath(fileName.toString());
        } else {
          throw new NullPointerException("CertificateFilename is null");
        }
      } else {
        throw new NullPointerException("Certificate filename is null");
      }
    } catch (IOException | CertificateException e) {
      getLogger().error("Error reading certificate from file: {}.", filePath, e);
    }
    throw new RuntimeException();
  }

  public void storeCertificate(X509Certificate certificate) throws IOException {
    CertificateCodec codec = new CertificateCodec(securityConfig, componentName);
    codec.writeCertificate(certificate);
  }

  public Set<X509Certificate> getLeafCertificates() {
    if (getCertPaths().isEmpty()) {
      getLogger().info("Leaf certificates are empty");
      return new HashSet<>();
    }
    return getCertPaths().stream()
        .map(certPath -> (X509Certificate) certPath.getCertificates().get(0))
        .collect(Collectors.toSet());
  }
}
