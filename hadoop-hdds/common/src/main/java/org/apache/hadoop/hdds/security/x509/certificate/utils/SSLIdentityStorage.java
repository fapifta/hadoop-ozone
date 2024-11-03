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
import org.apache.hadoop.hdds.security.ssl.ReloadingX509KeyManager;
import org.apache.hadoop.hdds.security.x509.certificate.client.CertificateNotification;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;
import org.apache.hadoop.hdds.security.x509.keys.KeyCodec;
import org.apache.hadoop.ozone.OzoneSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.function.Predicate;

/**
 * Certificate storage implementation responsible for reading the certificate client's own certificate and keys.
 */
public class SSLIdentityStorage extends CertificateStorage implements CertificateNotification {

  private static final Logger LOG = LoggerFactory.getLogger(SSLIdentityStorage.class);

  private String certId;
  private final KeyCodec keyCodec;
  private ReloadingX509KeyManager keyManager;

  public SSLIdentityStorage(SecurityConfig config, String componentName, String certId) {
    super(config, componentName);
    this.keyCodec = new KeyCodec(config, componentName);
    this.certId = certId;
  }

  @Override
  void insertCertsToKeystore(KeyStore keyStore, CertPath certPath) {
    try {
      PrivateKey privateKey = getPrivateKey();
      keyStore.setKeyEntry(((X509Certificate) certPath.getCertificates().get(0)).getSerialNumber().toString(),
          privateKey, "".toCharArray(), certPath.getCertificates().toArray(new Certificate[0]));
    } catch (KeyStoreException e) {
      LOG.error("Error while trying to insert keys to keystore", e);
    }
  }

  public X509Certificate getLeafCertificate() {
    return (X509Certificate) getCertPaths().get(0).getCertificates().get(0);
  }

  /**
   * Return only the certificate path that has the same id at the leaf certificate as the known certId.
   *
   * @return True if the Certificate path leaf certificate has the same id as the known certId, false otherwise
   */
  @Override
  public Predicate<CertPath> getCertificateFilter() {
    return certPath -> isLeafCertIdEqual(certPath, certId);
  }

  public PublicKey getPublicKey() {
    Path keyPath = getSecurityConfig().getKeyLocation(getComponentName());
    PublicKey publicKey = null;
    if (OzoneSecurityUtil.checkIfFileExist(keyPath,
        getSecurityConfig().getPublicKeyFileName())) {
      try {
        publicKey = keyCodec.readPublicKey();
      } catch (InvalidKeySpecException | NoSuchAlgorithmException
               | IOException e) {
        getLogger().error("Error while getting public key.", e);
      }
    }
    return publicKey;
  }

  public PrivateKey getPrivateKey() {
    Path keyPath = getSecurityConfig().getKeyLocation(getComponentName());
    PrivateKey privateKey = null;
    if (OzoneSecurityUtil.checkIfFileExist(keyPath,
        getSecurityConfig().getPrivateKeyFileName())) {
      try {
        privateKey = keyCodec.readPrivateKey();
      } catch (InvalidKeySpecException | NoSuchAlgorithmException
               | IOException e) {
        getLogger().error("Error while getting private key.", e);
      }
    }
    return privateKey;
  }

  private boolean isLeafCertIdEqual(CertPath certPath, String certSerial) {
    return ((X509Certificate) certPath.getCertificates().get(0)).getSerialNumber().toString().equals(certSerial);
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  public void setCertId(String certId) {
    this.certId = certId;
  }

  public void storeKeyPair(KeyPair keyPair) throws IOException {
    keyCodec.writeKey(keyPair);
  }

  public synchronized ReloadingX509KeyManager getKeyManager() throws CertificateException {
    try {
      if (keyManager == null) {
        keyManager = new ReloadingX509KeyManager(this);
      }
      return keyManager;
    } catch (IOException | GeneralSecurityException e) {
      throw new CertificateException("Failed to init keyManager", e, CertificateException.ErrorCode.KEYSTORE_ERROR);
    }
  }

  @Override
  public void notifyCertificateRenewed(String oldCertId, String newCertId) {
    keyManager.notifyCertificateRenewed(oldCertId, newCertId);
  }
}
