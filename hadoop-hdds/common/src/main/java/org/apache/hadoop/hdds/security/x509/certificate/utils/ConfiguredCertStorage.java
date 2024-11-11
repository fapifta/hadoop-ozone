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

import com.google.common.annotations.VisibleForTesting;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.keys.KeyCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Certificate storage implementation for reading and writing certificates configured as default in SecurityConfig.
 */
public class ConfiguredCertStorage extends CertificateStorage {

  private static final Logger LOG = LoggerFactory.getLogger(RotationHandlerStorage.class);

  public ConfiguredCertStorage(SecurityConfig securityConfig, String componentName) {
    super(securityConfig, componentName);
  }

  @Override
  public Predicate<Path> getFileFilter() {
    return path -> path.getFileName().toString().equals(getSecurityConfig().getCertificateFileName());
  }

  @Override
  Predicate<CertPath> getCertificateFilter() {
    return certPath -> true;
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  public String initWithExternalRootCA(SecurityConfig conf) {
    String externalRootCaLocation = conf.getExternalRootCaCert();
    Path extCertPath = Paths.get(externalRootCaLocation);
    Path extPrivateKeyPath = Paths.get(conf.getExternalRootCaPrivateKeyPath());
    String externalPublicKeyLocation = conf.getExternalRootCaPublicKeyPath();

    KeyCodec keyCodec = new KeyCodec(getSecurityConfig(), getComponentName());
    try {
      Path extCertParent = extCertPath.getParent();
      Path extCertName = extCertPath.getFileName();
      if (extCertParent == null || extCertName == null) {
        throw new IOException("External cert path is not correct: " +
            extCertPath);
      }
      CertPath certPath = getCertPath(extCertParent, extCertName.toString());
      Path extPrivateKeyParent = extPrivateKeyPath.getParent();
      Path extPrivateKeyFileName = extPrivateKeyPath.getFileName();
      if (extPrivateKeyParent == null || extPrivateKeyFileName == null) {
        throw new IOException("External private key path is not correct: " +
            extPrivateKeyPath);
      }
      PrivateKey privateKey = keyCodec.readPrivateKey(extPrivateKeyParent,
          extPrivateKeyFileName.toString());
      PublicKey publicKey;
      publicKey = readPublicKeyWithExternalData(
          externalPublicKeyLocation, keyCodec, certPath);
      keyCodec.writeKey(new KeyPair(publicKey, privateKey));
      storeDefaultCertificate(CertificateCodec.get().encode(certPath));
      X509Certificate certificate = (X509Certificate) (certPath.getCertificates().get(0));
      return certificate.getSerialNumber().toString();
    } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOG.error("External root CA certificate initialization failed", e);
      return null;
    }
  }

  private PublicKey readPublicKeyWithExternalData(
      String externalPublicKeyLocation, KeyCodec keyCodec, CertPath certPath
  ) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    PublicKey publicKey;
    if (externalPublicKeyLocation.isEmpty()) {
      publicKey = certPath.getCertificates().get(0).getPublicKey();
    } else {
      Path publicKeyPath = Paths.get(externalPublicKeyLocation);
      Path publicKeyPathFileName = publicKeyPath.getFileName();
      Path publicKeyParent = publicKeyPath.getParent();
      if (publicKeyPathFileName == null || publicKeyParent == null) {
        throw new IOException("Public key path incorrect: " + publicKeyParent);
      }
      publicKey = keyCodec.readPublicKey(
          publicKeyParent, publicKeyPathFileName.toString());
    }
    return publicKey;
  }

  @Override
  @VisibleForTesting
  public void writeCertificate(Path basePath, String fileName, String pemEncodedCertificate)
      throws IOException {
    super.writeCertificate(basePath, fileName, pemEncodedCertificate);
  }


  /**
   * Helper method that takes in a certificate path and a certificate and
   * generates a new certificate path starting with the new certificate
   * followed by all certificates in the specified path.
   */
  public static CertPath prependCertToCertPath(X509Certificate certificate, CertPath path) throws CertificateException {
    List<? extends Certificate> certificates = path.getCertificates();
    ArrayList<X509Certificate> updatedList = new ArrayList<>();
    updatedList.add(certificate);
    for (Certificate cert : certificates) {
      updatedList.add((X509Certificate) cert);
    }
    return CertificateFactory.getInstance("X.509").generateCertPath(updatedList);
  }
}
