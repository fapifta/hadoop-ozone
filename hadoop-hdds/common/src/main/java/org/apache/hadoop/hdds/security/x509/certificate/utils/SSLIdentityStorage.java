/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdds.security.x509.certificate.utils;

import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.keys.KeyCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Certificate storage implementation responsible for reading the certificate client's own certificate and keys.
 */
public class SSLIdentityStorage extends CertificateStorage {

  private static final Logger LOG = LoggerFactory.getLogger(SSLIdentityStorage.class);
  private final String certId;
  private final KeyCodec keyCodec;

  public SSLIdentityStorage(SecurityConfig config, String componentName, String certId) {
    super(config, componentName);
    this.keyCodec = new KeyCodec(config, componentName);
    this.certId = certId;
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
    try {
      PrivateKey privateKey = readPrivateKey();
      List<X509Certificate> certsFromPath =
          certPath.getCertificates().stream()
              .map(certificate -> (X509Certificate) certificate)
              .collect(Collectors.toList());
      keyStore.setKeyEntry(certsFromPath.get(0).getSerialNumber().toString(),
          privateKey, "".toCharArray(), certsFromPath.toArray(new X509Certificate[0]));
    } catch (KeyStoreException | InvalidKeySpecException | NoSuchAlgorithmException | IOException ignored) {
    }
  }

  @Override
  public List<CertPath> getCertificates() throws IOException {
    Path certificateLocation = getSecurityConfig().getCertificateLocation(getComponentName());
    try (Stream<Path> certFiles = Files.list(certificateLocation)) {
      return certFiles
          .filter(Files::isRegularFile)
          .map(this::readCertFile)
          .filter(certPath -> isLeafCertIdEqual(certPath, certId))
          .collect(Collectors.toList());
    }
  }

  public PublicKey readPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    return keyCodec.readPublicKey();
  }

  public PrivateKey readPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    return keyCodec.readPrivateKey();
  }

  private boolean isLeafCertIdEqual(CertPath certPath, String certSerial) {
    return ((X509Certificate) certPath.getCertificates().get(0)).getSerialNumber().toString().equals(certSerial);
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }
}
