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

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.ssl.ReloadingX509KeyManager;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClient;
import org.apache.hadoop.hdds.security.x509.certificate.client.CertificateNotification;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.apache.hadoop.ozone.OzoneSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;

import static org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage.InitResponse.FAILURE;
import static org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage.InitResponse.GETCERT;
import static org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage.InitResponse.SUCCESS;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.BOOTSTRAP_ERROR;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.CRYPTO_SIGNATURE_VERIFICATION_ERROR;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.CRYPTO_SIGN_ERROR;

/**
 * Certificate storage implementation responsible for reading the certificate client's own certificate and keys.
 */
public class SSLIdentityStorage extends CertificateStorage implements CertificateNotification {

  public static final Logger LOG = LoggerFactory.getLogger(SSLIdentityStorage.class);

  private String certId;
  private KeyStorage keyStorage;
  private ReloadingX509KeyManager keyManager;
  private Consumer<String> certIdSaveCallback;

  public SSLIdentityStorage(SecurityConfig config, String componentName, String certId) {
    super(config, componentName);
    this.certId = certId;
  }

  public SSLIdentityStorage(SecurityConfig config, String componentName, String certId,
      Consumer<String> certIdSaveCallback) {
    super(config, componentName);
    this.certId = certId;
    this.certIdSaveCallback = certIdSaveCallback;
  }

  @Override
  void insertCertsToKeystore(KeyStore keyStore, OzoneCertPath certPath) {
    try {
      PrivateKey privateKey = getPrivateKey();
      keyStore.setKeyEntry(certPath.getLeafCert().getSerialNumber().toString(),
          privateKey, "".toCharArray(), certPath.getCertificates().toArray(new Certificate[0]));
    } catch (KeyStoreException e) {
      LOG.error("Error while trying to insert keys to keystore", e);
    }
  }

  public X509Certificate getLeafCertificate() {
    List<OzoneCertPath> certPaths = getCertPaths();
    if (CollectionUtils.isEmpty(certPaths)) {
      return null;
    }
    return certPaths.get(0).getLeafCert();
  }

  private void initKeyStorage() {
    if (keyStorage == null) {
      keyStorage = new KeyStorage(getSecurityConfig(), getComponentName());
    }
  }

  /**
   * Return only the certificate path that has the same id at the leaf certificate as the known certId.
   *
   * @return True if the Certificate path leaf certificate has the same id as the known certId, false otherwise
   */
  @Override
  public Predicate<OzoneCertPath> getCertificateFilter() {
    return certPath -> isLeafCertIdEqual(certPath, certId);
  }

  public PublicKey getPublicKey() {
    Path keyPath = getSecurityConfig().getKeyLocation(getComponentName());
    PublicKey publicKey = null;
    if (OzoneSecurityUtil.checkIfFileExist(keyPath,
        getSecurityConfig().getPublicKeyFileName())) {
      try {
        initKeyStorage();
        publicKey = keyStorage.readPublicKey();
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
        initKeyStorage();
        privateKey = keyStorage.readPrivateKey();
      } catch (InvalidKeySpecException | NoSuchAlgorithmException
               | IOException e) {
        getLogger().error("Error while getting private key.", e);
      }
    }
    return privateKey;
  }

  public KeyPair getKeyPair() {
    return new KeyPair(getPublicKey(), getPrivateKey());
  }

  private boolean isLeafCertIdEqual(OzoneCertPath certPath, String certSerial) {
    return certPath.getLeafCert().getSerialNumber().toString().equals(certSerial);
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  public void setCertId(String certId) {
    this.certId = certId;
  }

  public void storeKeyPair(KeyPair keyPair) throws IOException {
    initKeyStorage();
    keyStorage.storeKey(keyPair);
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
  public synchronized void notifyCertificateRenewed(String newCertId) {
    if (keyManager != null) {
      keyManager.notifyCertificateRenewed(newCertId);
    }
  }


  /**
   * Initializes client by performing following actions.
   * 1. Create key dir if not created already.
   * 2. Generates and stores a keypair.
   * 3. Try to recover public key if private key and certificate is present
   * but public key is missing.
   * 4. Try to refetch certificate if public key and private key are present
   * but certificate is missing.
   * 5. Try to recover public key from private key(RSA only) if private key
   * is present but public key and certificate are missing, and refetch
   * certificate.
   * <p>
   * Truth table:
   * <pre>
   * {@code
   *  +--------------+---------------+--------------+---------------------+
   *  | Private Key  | Public Keys   | Certificate  |   Result            |
   *  +--------------+---------------+--------------+---------------------+
   *  | False  (0)   | False   (0)   | False  (0)   |   GETCERT->SUCCESS  |
   *  | False  (0)   | False   (0)   | True   (1)   |   FAILURE           |
   *  | False  (0)   | True    (1)   | False  (0)   |   FAILURE           |
   *  | False  (0)   | True    (1)   | True   (1)   |   FAILURE           |
   *  | True   (1)   | False   (0)   | False  (0)   |   GETCERT->SUCCESS  |
   *  | True   (1)   | False   (0)   | True   (1)   |   SUCCESS           |
   *  | True   (1)   | True    (1)   | False  (0)   |   GETCERT->SUCCESS  |
   *  | True   (1)   | True    (1)   | True   (1)   |   SUCCESS           |
   *  +--------------+-----------------+--------------+----------------+
   * }
   * </pre>
   * Success in following cases:
   * 1. If keypair as well certificate is available.
   * 2. If private key and certificate is available and public key is
   * recovered successfully.
   * 3. If private key and public key are present while certificate is
   * missing, certificate is refetched successfully.
   * 4. If private key is present while public key and certificate are missing,
   * public key is recovered and certificate is refetched successfully.
   * <p>
   * Throw exception in following cases:
   * 1. If private key is missing.
   * 2. If private key or certificate is present, public key is missing,
   * and cannot recover public key from private key or certificate
   * 3. If refetch certificate fails.
   */
  public synchronized void initWithRecovery(CertificateClient certificateClient) throws IOException {
    recoverStateIfNeeded(init(), certificateClient);
  }


  @VisibleForTesting
  public synchronized InitResponse init() throws IOException {
    X509Certificate certificate = getCertificate();
    PrivateKey pvtKey = getPrivateKey();
    PublicKey pubKey = getPublicKey();
    //The logic here: if we don't find a certificate, just throw away keys and ask for a new certificate
    //If there is a certificate, try finding keys/restoring public key. If keys are there or can be restored, then
    // success, otherwise failure.
    if (certificate == null || isSingularLeafCert(getCertPaths().get(0))) {
      deleteKeys();
      bootstrapClientKeys();
      return GETCERT;
    }
    if (pvtKey == null) {
      return FAILURE;
    }
    //Cert and private key are present
    if (pubKey != null) {
      return SUCCESS;
    }
    if (recoverPublicKey()) {
      return SUCCESS;
    }
    return FAILURE;
  }

  private void getAndStoreAllRootCAs(Path certificatePath, CertificateClient certificateClient)
      throws IOException {
    List<String> rootCAPems = certificateClient.getAllRootCaCertificates();
    for (String rootCAPem : rootCAPems) {
      storeCertificate(rootCAPem, CAType.ROOT, certificatePath);
    }
  }

  private void deleteKeys() throws IOException {
    File currentKeyDir = new File(getSecurityConfig().getKeyLocation(getComponentName()).toString());
    FileUtils.deleteDirectory(currentKeyDir);
  }

  private boolean isSingularLeafCert(OzoneCertPath seeIfCertPath) {
    boolean isSingularLeafCert = seeIfCertPath != null && seeIfCertPath.getCertificates().size() == 1 &&
        !isSelfSignedCertificate(seeIfCertPath.getLeafCert());
    if (isSingularLeafCert) {
      getLogger().info("Found singular cert path with id: {}, proceeding to reinit certificates.",
          (seeIfCertPath.getLeafCert()).getSerialNumber());
    }
    return isSingularLeafCert;
  }

  /**
   * Recover the state if needed.
   */
  public void recoverStateIfNeeded(InitResponse state, CertificateClient certClient) throws IOException {
    String upperCaseComponent = getComponentName().toUpperCase();
    getLogger().info("Init response: {}", state);
    switch (state) {
    case SUCCESS:
      if (validateKeyPairAndCertificate()) {
        getLogger().info("Initialization successful, case:{}.", state);
      } else {
        throw new RuntimeException(upperCaseComponent + " security initialization failed.");
      }
      break;
    case GETCERT:
      Path certLocation = getSecurityConfig().getCertificateLocation(getComponentName());
      String signedCertPath = certClient.signCertificate(certClient.configureCSRBuilder().build());
      // Return the default certificate ID
      String signedCertId = storeCertificate(signedCertPath, CAType.NONE, certLocation);
      getAndStoreAllRootCAs(certLocation, certClient);
      setCertId(signedCertId);
      if (certIdSaveCallback != null) {
        certIdSaveCallback.accept(signedCertId);
      } else {
        throw new RuntimeException(upperCaseComponent + " doesn't have " +
            "the certIdSaveCallback set. The new " +
            "certificate ID " + signedCertId + " cannot be persisted to " +
            "the VERSION file");
      }
      getLogger().info("Successfully stored {} signed certificate, case:{}.",
          upperCaseComponent, state);
      validateKeyPairAndCertificate();
      break;
    case FAILURE:
    default:
      getLogger().error("{} security initialization failed. " +
          "Init response: {}", upperCaseComponent, state);
      throw new RuntimeException(upperCaseComponent +
          " security initialization failed.");
    }
  }

  /**
   * Validate keypair and certificate.
   */
  protected boolean validateKeyPairAndCertificate() throws
      CertificateException {
    if (validateKeyPair(getPublicKey())) {
      getLogger().info("Keypair validated.");
      // TODO: Certificates cryptographic validity can be checked as well.
      if (getCertificate() != null && validateKeyPair(getCertificate().getPublicKey())) {
        getLogger().info("Keypair validated with certificate.");
      } else {
        getLogger().error("Stored certificate is generated with different " +
            "private key.");
        return false;
      }
    } else {
      getLogger().error("Keypair validation failed.");
      return false;
    }
    return true;
  }

  /**
   * Tries to recover public key from certificate. Also validates recovered
   * public key.
   */
  protected boolean recoverPublicKey() throws CertificateException {
    PublicKey pubKey = getLeafCertificate().getPublicKey();
    try {

      if (validateKeyPair(pubKey)) {
        initKeyStorage();
        keyStorage.storePublicKey(pubKey);
      } else {
        getLogger().error("Can't recover public key " +
            "corresponding to private key.");
        return false;
      }
    } catch (IOException e) {
      throw new CertificateException("Error while trying to recover " +
          "public key.", e, BOOTSTRAP_ERROR);
    }
    return true;
  }

  /**
   * Validates public and private key of certificate client.
   *
   * @param pubKey
   */
  protected boolean validateKeyPair(PublicKey pubKey)
      throws CertificateException {
    byte[] challenge =
        RandomStringUtils.random(1000, 0, 0, false, false, null,
            new SecureRandom()).getBytes(StandardCharsets.UTF_8);
    return verifySignature(challenge, signData(challenge), pubKey);
  }

  /**
   * Bootstrap the client by creating keypair and storing it in configured
   * location.
   */
  protected void bootstrapClientKeys() throws CertificateException {
    Path keyPath = getSecurityConfig().getKeyLocation(getComponentName());
    if (Files.notExists(keyPath)) {
      try {
        Files.createDirectories(keyPath);
      } catch (IOException e) {
        throw new CertificateException("Error while creating directories " +
            "for certificate storage.", BOOTSTRAP_ERROR);
      }
    }
    initKeyStorage();
    createKeyPair(keyStorage);
  }

  protected KeyPair createKeyPair(KeyStorage storage) throws CertificateException {
    HDDSKeyGenerator keyGenerator = new HDDSKeyGenerator(getSecurityConfig());
    KeyPair keyPair;
    try {
      keyPair = keyGenerator.generateKey();
      storage.storeKey(keyPair);
    } catch (NoSuchProviderException | NoSuchAlgorithmException
             | IOException e) {
      getLogger().error("Error while bootstrapping certificate client.", e);
      throw new CertificateException("Error while bootstrapping certificate.",
          BOOTSTRAP_ERROR);
    }
    return keyPair;
  }

  /**
   * Verifies a digital Signature, given the signature and the certificate of
   * the signer.
   *
   * @param data      - Data in byte array.
   * @param signature - Byte Array containing the signature.
   * @param pubKey    - Certificate of the Signer.
   * @return true if verified, false if not.
   */
  private boolean verifySignature(byte[] data, byte[] signature,
      PublicKey pubKey) throws CertificateException {
    try {
      Signature sign = Signature.getInstance(getSecurityConfig().getSignatureAlgo(), getSecurityConfig().getProvider());
      sign.initVerify(pubKey);
      sign.update(data);
      return sign.verify(signature);
    } catch (NoSuchAlgorithmException | NoSuchProviderException
             | InvalidKeyException | SignatureException e) {
      getLogger().error("Error while signing the stream", e);
      throw new CertificateException("Error while signing the stream", e,
          CRYPTO_SIGNATURE_VERIFICATION_ERROR);
    }
  }

  /**
   * Creates digital signature over the data stream using the s private key.
   *
   * @param data - Data to sign.
   * @throws CertificateException - on Error.
   */
  public byte[] signData(byte[] data) throws CertificateException {
    try {
      Signature sign = Signature.getInstance(getSecurityConfig().getSignatureAlgo(), getSecurityConfig().getProvider());

      sign.initSign(getPrivateKey());
      sign.update(data);

      return sign.sign();
    } catch (NoSuchAlgorithmException | NoSuchProviderException
             | InvalidKeyException | SignatureException e) {
      getLogger().error("Error while signing the stream", e);
      throw new CertificateException("Error while signing the stream", e,
          CRYPTO_SIGN_ERROR);
    }
  }

  public static boolean isSelfSignedCertificate(X509Certificate cert) {
    return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
  }

  /**
   * Represents initialization response of client.
   * 1. SUCCESS: Means client is initialized successfully and all required
   * files are in expected state.
   * 2. FAILURE: Initialization failed due to some unrecoverable error.
   * 3. GETCERT: Bootstrap of keypair is successful but certificate is not
   * found. Client should request SCM signed certificate.
   */
  public enum InitResponse {
    SUCCESS,
    FAILURE,
    GETCERT
  }

  private X509Certificate getCertificate() {
    OzoneCertPath currentCertPath = getCertPath();
    if (currentCertPath == null || currentCertPath.getCertificates() == null) {
      return null;
    }
    return currentCertPath.getLeafCert();
  }

  private OzoneCertPath getCertPath() {
    if (getCertPaths().isEmpty()) {
      getLogger().info("No certificates found for SSLIdentityService");
      return null;
    }
    return getCertPaths().get(0);
  }
}
