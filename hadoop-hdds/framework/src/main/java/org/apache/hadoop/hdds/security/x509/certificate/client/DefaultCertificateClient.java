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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.hdds.protocol.proto.SCMSecurityProtocolProtos.SCMGetCertResponseProto;
import org.apache.hadoop.hdds.protocolPB.SCMSecurityProtocolClientSideTranslatorPB;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.exception.OzoneSecurityException;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage;
import org.apache.hadoop.hdds.security.x509.certificate.utils.TrustedCertStorage;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.apache.hadoop.hdds.security.x509.certificate.utils.KeyStorage;
import org.apache.hadoop.ozone.OzoneSecurityUtil;

import com.google.common.base.Preconditions;
import org.apache.commons.lang3.RandomStringUtils;

import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX;
import static org.apache.hadoop.hdds.security.exception.OzoneSecurityException.ResultCodes.OM_PUBLIC_PRIVATE_KEY_FILE_NOT_EXIST;
import static org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClient.InitResponse.FAILURE;
import static org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClient.InitResponse.GETCERT;
import static org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClient.InitResponse.SUCCESS;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.BOOTSTRAP_ERROR;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.CRYPTO_SIGNATURE_VERIFICATION_ERROR;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.CRYPTO_SIGN_ERROR;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.RENEW_ERROR;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.ROLLBACK_ERROR;

import org.slf4j.Logger;

/**
 * Default Certificate client implementation. It provides certificate
 * operations that needs to be performed by certificate clients in the Ozone
 * eco-system.
 */
public abstract class DefaultCertificateClient implements CertificateClient {

  private static final String CERT_FILE_EXTENSION = ".crt";
  public static final String CERT_FILE_NAME_FORMAT = "%s" + CERT_FILE_EXTENSION;

  private final Logger logger;
  private final SecurityConfig securityConfig;
  private final KeyStorage keyStorage;
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private String certSerialId;
  private String component;
  private final String threadNamePrefix;

  private ScheduledExecutorService executorService;
  private Consumer<String> certIdSaveCallback;
  private Runnable shutdownCallback;
  private SCMSecurityProtocolClientSideTranslatorPB scmSecurityClient;
  private final Set<CertificateNotification> notificationReceivers;
  private RootCaRotationPoller rootCaRotationPoller;
  private SSLIdentityStorage sslIdentityStorage;
  private TrustedCertStorage trustedCertStorage;

  @SuppressWarnings("checkstyle:ParameterNumber")
  protected DefaultCertificateClient(
      SecurityConfig securityConfig,
      SCMSecurityProtocolClientSideTranslatorPB scmSecurityClient,
      Logger log,
      String certSerialId,
      String component,
      String threadNamePrefix,
      Consumer<String> saveCertId,
      Runnable shutdown, SSLIdentityStorage sslIdentityStorage, TrustedCertStorage trustedCertStorage) {
    Objects.requireNonNull(securityConfig);
    this.securityConfig = securityConfig;
    this.scmSecurityClient = scmSecurityClient;
    keyStorage = new KeyStorage(securityConfig, component);
    this.logger = log;
    this.component = component;
    this.threadNamePrefix = threadNamePrefix;
    this.certIdSaveCallback = saveCertId;
    this.shutdownCallback = shutdown;
    this.notificationReceivers = new HashSet<>();
    this.sslIdentityStorage = sslIdentityStorage;
    this.trustedCertStorage = trustedCertStorage;
    notificationReceivers.add(sslIdentityStorage);
    notificationReceivers.add(trustedCertStorage);
    updateCertSerialId(certSerialId);
  }

  /**
   * Load all certificates from configured location.
   * */
  private synchronized void loadAllCertificates() {
    Path path = securityConfig.getCertificateLocation(component);
    if (!path.toFile().exists() || certSerialId == null) {
      return;
    }
    sslIdentityStorage.setCertId(certSerialId);
    if (shouldStartCertificateRenewerService()) {
      if (securityConfig.isAutoCARotationEnabled()) {
        startRootCaRotationPoller();
      }
      List<CertPath> certPaths = sslIdentityStorage.getCertPaths();
      if (!certPaths.isEmpty() && executorService == null) {
        startCertificateRenewerService();
      } else {
        if (executorService != null) {
          getLogger().debug("CertificateRenewerService is already started.");
        } else {
          getLogger().warn("Component certificate was not loaded.");
        }
      }
    } else {
      getLogger().info("CertificateRenewerService and root ca rotation " +
          "polling is disabled for {}", component);
    }
  }

  protected String threadNamePrefix() {
    return threadNamePrefix;
  }

  private void startRootCaRotationPoller() {
    if (rootCaRotationPoller == null) {
      rootCaRotationPoller =
          new RootCaRotationPoller(securityConfig, trustedCertStorage.getLeafCertificates(), scmSecurityClient,
              threadNamePrefix);
      rootCaRotationPoller.addRootCARotationProcessor(
          this::getRootCaRotationListener);
      rootCaRotationPoller.run();
    } else {
      getLogger().debug("Root CA certificate rotation poller is already " +
          "started.");
    }
  }

  @Override
  public synchronized void registerRootCARotationListener(
      Function<List<X509Certificate>, CompletableFuture<Void>> listener) {
    if (securityConfig.isAutoCARotationEnabled()) {
      rootCaRotationPoller.addRootCARotationProcessor(listener);
    }
  }

  /**
   * Returns the private key of the specified  if it exists on the local
   * system.
   *
   * @return private key or Null if there is no data.
   */
  public synchronized PrivateKey getPrivateKey() {
    if (privateKey != null) {
      return privateKey;
    }

    Path keyPath = securityConfig.getKeyLocation(component);
    if (OzoneSecurityUtil.checkIfFileExist(keyPath,
        securityConfig.getPrivateKeyFileName())) {
      try {
        privateKey = keyStorage.readPrivateKey();
      } catch (InvalidKeySpecException | NoSuchAlgorithmException
          | IOException e) {
        getLogger().error("Error while getting private key.", e);
      }
    }
    return privateKey;
  }

  /**
   * Returns the public key of the specified if it exists on the local system.
   *
   * @return public key or Null if there is no data.
   */
  public synchronized PublicKey getPublicKey() {
    if (publicKey != null) {
      return publicKey;
    }

    Path keyPath = securityConfig.getKeyLocation(component);
    if (OzoneSecurityUtil.checkIfFileExist(keyPath,
        securityConfig.getPublicKeyFileName())) {
      try {
        publicKey = keyStorage.readPublicKey();
      } catch (InvalidKeySpecException | NoSuchAlgorithmException
          | IOException e) {
        getLogger().error("Error while getting public key.", e);
      }
    }
    return publicKey;
  }

  @Override
  public X509Certificate getCertificate() {
    CertPath currentCertPath = getCertPath();
    if (currentCertPath == null || currentCertPath.getCertificates() == null) {
      return null;
    }
    return firstCertificateFrom(currentCertPath);
  }

  private synchronized CertPath getCertPath() {
    if (sslIdentityStorage.getCertPaths().isEmpty()) {
      getLogger().info("No certificates found for certificate client with certificate id: {}", certSerialId);
      return null;
    }
    return sslIdentityStorage.getCertPaths().get(0);
  }

  /**
   * Creates digital signature over the data stream using the s private key.
   *
   * @param data - Data to sign.
   * @throws CertificateException - on Error.
   */
  public byte[] signData(byte[] data) throws CertificateException {
    try {
      Signature sign = Signature.getInstance(securityConfig.getSignatureAlgo(),
          securityConfig.getProvider());

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

  /**
   * Verifies a digital Signature, given the signature and the certificate of
   * the signer.
   *
   * @param data - Data in byte array.
   * @param signature - Byte Array containing the signature.
   * @param cert - Certificate of the Signer.
   * @return true if verified, false if not.
   */
  @Override
  public boolean verifySignature(byte[] data, byte[] signature,
      X509Certificate cert) throws CertificateException {
    try {
      Signature sign = Signature.getInstance(securityConfig.getSignatureAlgo(),
          securityConfig.getProvider());
      sign.initVerify(cert);
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
   * Verifies a digital Signature, given the signature and the certificate of
   * the signer.
   *
   * @param data - Data in byte array.
   * @param signature - Byte Array containing the signature.
   * @param pubKey - Certificate of the Signer.
   * @return true if verified, false if not.
   */
  private boolean verifySignature(byte[] data, byte[] signature,
      PublicKey pubKey) throws CertificateException {
    try {
      Signature sign = Signature.getInstance(securityConfig.getSignatureAlgo(),
          securityConfig.getProvider());
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
   * Returns a CSR builder that can be used to creates a Certificate signing
   * request.
   *
   * @return CertificateSignRequest.Builder
   */
  @Override
  public CertificateSignRequest.Builder configureCSRBuilder() throws SCMSecurityException {
    return new CertificateSignRequest.Builder()
        .setConfiguration(securityConfig)
        .addInetAddresses()
        .setDigitalEncryption(true)
        .setDigitalSignature(true);
  }

  /**
   *
   * Initializes client by performing following actions.
   * 1. Create key dir if not created already.
   * 2. Generates and stores a keypair.
   * 3. Try to recover public key if private key and certificate is present
   *    but public key is missing.
   * 4. Try to refetch certificate if public key and private key are present
   *    but certificate is missing.
   * 5. Try to recover public key from private key(RSA only) if private key
   *    is present but public key and certificate are missing, and refetch
   *    certificate.
   *
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
   *    recovered successfully.
   * 3. If private key and public key are present while certificate is
   *    missing, certificate is refetched successfully.
   * 4. If private key is present while public key and certificate are missing,
   *    public key is recovered and certificate is refetched successfully.
   *
   * Throw exception in following cases:
   * 1. If private key is missing.
   * 2. If private key or certificate is present, public key is missing,
   *    and cannot recover public key from private key or certificate
   * 3. If refetch certificate fails.
   */
  @Override
  public synchronized void initWithRecovery() throws IOException {
    recoverStateIfNeeded(init());
  }

  @VisibleForTesting
  public synchronized InitResponse init() throws IOException {
    X509Certificate certificate = getCertificate();
    PrivateKey pvtKey = getPrivateKey();
    PublicKey pubKey = getPublicKey();
    //The logic here: if we don't find a certificate, just throw away keys and ask for a new certificate
    //If there is a certificate, try finding keys/restoring public key. If keys are there or can be restored, then
    // success, otherwise failure.
    if (certificate == null || isSingularLeafCert(getCertPath())) {
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

  private void deleteKeys() throws IOException {
    File currentKeyDir = new File(getSecurityConfig().getKeyLocation(component).toString());
    FileUtils.deleteDirectory(currentKeyDir);
  }

  private boolean isSingularLeafCert(CertPath seeIfCertPath) {
    boolean isSingularLeafCert = seeIfCertPath != null && seeIfCertPath.getCertificates().size() == 1 &&
        !isSelfSignedCertificate((X509Certificate) seeIfCertPath.getCertificates().get(0));
    if (isSingularLeafCert) {
      getLogger().info("Found singular cert path with id: {}, proceeding to reinit certificates.",
          ((X509Certificate) seeIfCertPath.getCertificates().get(0)).getSerialNumber());
    }
    return isSingularLeafCert;
  }

  public static boolean isSelfSignedCertificate(X509Certificate cert) {
    return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
  }

  private X509Certificate firstCertificateFrom(CertPath certificatePath) {
    return (X509Certificate) certificatePath.getCertificates().get(0);
  }

  /**
   * Recover the state if needed.
   * */
  protected void recoverStateIfNeeded(InitResponse state) throws IOException {
    String upperCaseComponent = component.toUpperCase();
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
      Path certLocation = securityConfig.getCertificateLocation(getComponentName());
      String signedCertPath = signCertificate(configureCSRBuilder().build());
      // Return the default certificate ID
      String certId = sslIdentityStorage.storeCertificate(signedCertPath, CAType.NONE, certLocation);
      updateCertSerialId(certId);
      getAndStoreAllRootCAs(certLocation);
      if (certIdSaveCallback != null) {
        certIdSaveCallback.accept(certId);
      } else {
        throw new RuntimeException(upperCaseComponent + " doesn't have " +
            "the certIdSaveCallback set. The new " +
            "certificate ID " + certId + " cannot be persisted to " +
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
   * */
  protected boolean validateKeyPairAndCertificate() throws
      CertificateException {
    if (validateKeyPair(getPublicKey())) {
      getLogger().info("Keypair validated.");
      // TODO: Certificates cryptographic validity can be checked as well.
      if (validateKeyPair(getCertificate().getPublicKey())) {
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
   * */
  protected boolean recoverPublicKey() throws CertificateException {
    PublicKey pubKey = getCertificate().getPublicKey();
    try {

      if (validateKeyPair(pubKey)) {
        keyStorage.storePublicKey(pubKey);
        publicKey = pubKey;
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
   * */
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
   * */
  protected void bootstrapClientKeys() throws CertificateException {
    Path keyPath = securityConfig.getKeyLocation(component);
    if (Files.notExists(keyPath)) {
      try {
        Files.createDirectories(keyPath);
      } catch (IOException e) {
        throw new CertificateException("Error while creating directories " +
            "for certificate storage.", BOOTSTRAP_ERROR);
      }
    }
    KeyPair keyPair = createKeyPair(keyStorage);
    privateKey = keyPair.getPrivate();
    publicKey = keyPair.getPublic();
  }

  protected KeyPair createKeyPair(KeyStorage storage) throws CertificateException {
    HDDSKeyGenerator keyGenerator = new HDDSKeyGenerator(securityConfig);
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

  public Logger getLogger() {
    return logger;
  }

  public String getComponentName() {
    return component;
  }

  /**
   * Register a receiver that will be called after the certificate renewed.
   *
   * @param receiver
   */
  @Override
  public void registerNotificationReceiver(CertificateNotification receiver) {
    synchronized (notificationReceivers) {
      notificationReceivers.add(receiver);
    }
  }

  /**
   * Notify all certificate renewal receivers that the certificate is renewed.
   *
   */
  protected void notifyNotificationReceivers(String oldCaCertId,
      String newCaCertId) {
    synchronized (notificationReceivers) {
      notificationReceivers.forEach(r -> r.notifyCertificateRenewed(oldCaCertId, newCaCertId));
    }
  }

  @Override
  public synchronized void close() throws IOException {
    if (executorService != null) {
      executorService.shutdownNow();
      executorService = null;
    }

    if (rootCaRotationPoller != null) {
      rootCaRotationPoller.close();
    }
  }

  /**
   * Check how much time before certificate will enter expiry grace period.
   * @return Duration, time before certificate enters the grace
   *                   period defined by "hdds.x509.renew.grace.duration"
   */
  public Duration timeBeforeExpiryGracePeriod(X509Certificate certificate) {
    Duration gracePeriod = securityConfig.getRenewalGracePeriod();
    Date expireDate = certificate.getNotAfter();
    LocalDateTime gracePeriodStart = expireDate.toInstant()
        .minus(gracePeriod).atZone(ZoneId.systemDefault()).toLocalDateTime();
    LocalDateTime currentTime = LocalDateTime.now();
    if (gracePeriodStart.isBefore(currentTime)) {
      // Cert is already in grace period time.
      return Duration.ZERO;
    } else {
      return Duration.between(currentTime, gracePeriodStart);
    }
  }

  /**
   * Renew keys and certificate. Save the keys are certificate to disk in new
   * directories, swap the current key directory and certs directory with the
   * new directories.
   * @param force check certificate expiry time again if force is false.
   * @return String, new certificate ID
   * */
  public String renewAndStoreKeyAndCertificate(boolean force)
      throws CertificateException {
    if (!force) {
      synchronized (this) {
        Preconditions.checkArgument(
            timeBeforeExpiryGracePeriod(firstCertificateFrom(getCertPath()))
                .isZero());
      }
    }

    String newKeyPath = securityConfig.getKeyLocation(component)
        .toString() + HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX;
    String newCertPath = securityConfig.getCertificateLocation(component)
        .toString() + HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX;
    File newKeyDir = new File(newKeyPath);
    File newCertDir = new File(newCertPath);
    try {
      FileUtils.deleteDirectory(newKeyDir);
      FileUtils.deleteDirectory(newCertDir);
      Files.createDirectories(newKeyDir.toPath());
      Files.createDirectories(newCertDir.toPath());
    } catch (IOException e) {
      throw new CertificateException("Error while deleting/creating " +
          newKeyPath + " or " + newCertPath + " directories to cleanup " +
          " certificate storage. ", e, RENEW_ERROR);
    }

    // Generate key
    KeyStorage newKeyStorage = new KeyStorage(securityConfig, newKeyDir.toPath());
    KeyPair newKeyPair;
    try {
      newKeyPair = createKeyPair(newKeyStorage);
    } catch (CertificateException e) {
      throw new CertificateException("Error while creating new key pair.",
          e, RENEW_ERROR);
    }

    // Get certificate signed
    String newCertSerialId;
    try {
      CertificateSignRequest.Builder csrBuilder = configureCSRBuilder();
      csrBuilder.setKey(newKeyPair);
      Path certificatePath = Paths.get(newCertPath);
      String encoodedCert = signCertificate(csrBuilder.build());
      // Return the default certificate ID
      newCertSerialId = sslIdentityStorage.storeCertificate(encoodedCert, CAType.NONE, certificatePath);
      updateCertSerialId(newCertSerialId);
      getAndStoreAllRootCAs(certificatePath);
    } catch (Exception e) {
      throw new CertificateException("Error while signing and storing new" +
          " certificates.", e, RENEW_ERROR);
    }

    // switch Key and Certs directory on disk
    File currentKeyDir = new File(
        securityConfig.getKeyLocation(component).toString());
    File currentCertDir = new File(
        securityConfig.getCertificateLocation(component).toString());
    File backupKeyDir = new File(
        securityConfig.getKeyLocation(component).toString() +
            HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX);
    File backupCertDir = new File(
        securityConfig.getCertificateLocation(component).toString() +
            HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX);

    try {
      Files.move(currentKeyDir.toPath(), backupKeyDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      // Cannot move current key dir to the backup dir
      throw new CertificateException("Failed to move " +
          currentKeyDir.getAbsolutePath() +
          " to " + backupKeyDir.getAbsolutePath() + " during " +
          "certificate renew.", RENEW_ERROR);
    }

    try {
      Files.move(currentCertDir.toPath(), backupCertDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      // Cannot move current cert dir to the backup dir
      rollbackBackupDir(currentKeyDir, currentCertDir, backupKeyDir,
          backupCertDir);
      throw new CertificateException("Failed to move " +
          currentCertDir.getAbsolutePath() +
          " to " + backupCertDir.getAbsolutePath() + " during " +
          "certificate renew.", RENEW_ERROR);
    }

    try {
      Files.move(newKeyDir.toPath(), currentKeyDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      // Cannot move new dir as the current dir
      String msg = "Failed to move " + newKeyDir.getAbsolutePath() +
          " to " + currentKeyDir.getAbsolutePath() +
          " during certificate renew.";
      // rollback
      rollbackBackupDir(currentKeyDir, currentCertDir, backupKeyDir,
          backupCertDir);
      throw new CertificateException(msg, RENEW_ERROR);
    }

    try {
      Files.move(newCertDir.toPath(), currentCertDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      // Cannot move new dir as the current dir
      String msg = "Failed to move " + newCertDir.getAbsolutePath() +
          " to " + currentCertDir.getAbsolutePath() +
          " during certificate renew.";
      // delete currentKeyDir which is moved from new key directory
      try {
        FileUtils.deleteDirectory(new File(currentKeyDir.toString()));
      } catch (IOException e1) {
        getLogger().error("Failed to delete current KeyDir {} which is moved " +
            " from the newly generated KeyDir {}", currentKeyDir, newKeyDir, e);
        throw new CertificateException(msg, RENEW_ERROR);
      }
      // rollback
      rollbackBackupDir(currentKeyDir, currentCertDir, backupKeyDir,
          backupCertDir);
      throw new CertificateException(msg, RENEW_ERROR);
    }

    getLogger().info("Successful renew key and certificate." +
        " New certificate {}.", newCertSerialId);
    return newCertSerialId;
  }

  private void rollbackBackupDir(File currentKeyDir, File currentCertDir,
      File backupKeyDir, File backupCertDir) throws CertificateException {
    // move backup dir back as current dir
    try {
      Files.move(backupKeyDir.toPath(), currentKeyDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      String msg = "Failed to move " + backupKeyDir.getAbsolutePath() +
          " back to " + currentKeyDir.getAbsolutePath() +
          " during rollback.";
      // Need a manual recover process.
      throw new CertificateException(msg, ROLLBACK_ERROR);
    }

    try {
      Files.move(backupCertDir.toPath(), currentCertDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      String msg = "Failed to move " + backupCertDir.getAbsolutePath() +
          " back to " + currentCertDir.getAbsolutePath()  +
          " during rollback.";
      // Need a manual recover process.
      throw new CertificateException(msg, ROLLBACK_ERROR);
    }

    Preconditions.checkArgument(currentCertDir.exists());
    Preconditions.checkArgument(currentKeyDir.exists());
  }

  /**
   * Delete old backup key and cert directory.
   */
  public void cleanBackupDir() {
    File backupKeyDir = new File(
        securityConfig.getKeyLocation(component).toString() +
            HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX);
    File backupCertDir = new File(
        securityConfig.getCertificateLocation(component).toString() +
            HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX);
    if (backupKeyDir.exists()) {
      try {
        FileUtils.deleteDirectory(backupKeyDir);
      } catch (IOException e) {
        getLogger().error("Error while deleting {} directories for " +
            "certificate storage cleanup.", backupKeyDir, e);
      }
    }
    if (backupCertDir.exists()) {
      try {
        FileUtils.deleteDirectory(backupCertDir);
      } catch (IOException e) {
        getLogger().error("Error while deleting {} directories for " +
            "certificate storage cleanup.", backupCertDir, e);
      }
    }
  }

  public synchronized void reloadKeyAndCertificate(String newCertId) {
    privateKey = null;
    publicKey = null;

    String oldCaCertId = updateCertSerialId(newCertId);
    getLogger().info("Reset and reloaded key and all certificates for new " +
        "certificate {}.", newCertId);

    notifyNotificationReceivers(oldCaCertId, newCertId);
  }

  public SecurityConfig getSecurityConfig() {
    return securityConfig;
  }

  private synchronized String updateCertSerialId(String newCertSerialId) {
    certSerialId = newCertSerialId;
    getLogger().info("Certificate serial ID set to {}", certSerialId);
    sslIdentityStorage.setCertId(certSerialId);
    loadAllCertificates();
    return certSerialId;
  }

  protected abstract SCMGetCertResponseProto sign(CertificateSignRequest request) throws IOException;

  public String signCertificate(CertificateSignRequest csr)
      throws CertificateException {
    try {
      return sign(csr).getX509Certificate();
    } catch (IOException e) {
      logger.error("Error while signing signed certificate.", e);
      throw new CertificateException(
          "Error while signing SCM signed certificate.", e);
    }
  }

  private void getAndStoreAllRootCAs(Path certificatePath)
      throws IOException {
    List<String> rootCAPems = scmSecurityClient.getAllRootCaCertificates();
    for (String rootCAPem : rootCAPems) {
      trustedCertStorage.storeCertificate(rootCAPem, CAType.ROOT, certificatePath);
    }
  }

  public SCMSecurityProtocolClientSideTranslatorPB getScmSecureClient() {
    return scmSecurityClient;
  }

  public String getCertSerialId() {
    return certSerialId;
  }

  protected TrustedCertStorage getTrustedCertStorage() {
    return trustedCertStorage;
  }

  protected boolean shouldStartCertificateRenewerService() {
    return true;
  }

  public synchronized CompletableFuture<Void> getRootCaRotationListener(
      List<X509Certificate> rootCAs) {
    if (trustedCertStorage.getLeafCertificates().containsAll(rootCAs)) {
      return CompletableFuture.completedFuture(null);
    }
    CertificateRenewerService renewerService =
        new CertificateRenewerService(
            true, rootCaRotationPoller::setCertificateRenewalError);
    return CompletableFuture.runAsync(renewerService, executorService);
  }

  public synchronized void startCertificateRenewerService() {
    Preconditions.checkNotNull(getCertificate(),
        "Component certificate should not be empty");
    // Schedule task to refresh certificate before it expires
    Duration gracePeriod = securityConfig.getRenewalGracePeriod();
    long timeBeforeGracePeriod =
        timeBeforeExpiryGracePeriod(getCertificate()).toMillis();
    // At least three chances to renew the certificate before it expires
    long interval =
        Math.min(gracePeriod.toMillis() / 3, TimeUnit.DAYS.toMillis(1));

    if (executorService == null) {
      executorService = Executors.newScheduledThreadPool(1,
          new ThreadFactoryBuilder()
              .setNameFormat(threadNamePrefix + getComponentName()
                  + "-CertificateRenewerService")
              .setDaemon(true).build());
    }
    this.executorService.scheduleAtFixedRate(
        new CertificateRenewerService(false, () -> {
        }),
        // The Java mills resolution is 1ms, add 1ms to avoid task scheduled
        // ahead of time.
        timeBeforeGracePeriod + 1, interval, TimeUnit.MILLISECONDS);
    getLogger().info("CertificateRenewerService for {} is started with " +
            "first delay {} ms and interval {} ms.", component,
        timeBeforeGracePeriod, interval);
  }

  /**
   * Task to monitor certificate lifetime and renew the certificate if needed.
   */
  public class CertificateRenewerService implements Runnable {
    private boolean forceRenewal;
    private Runnable rotationErrorCallback;

    public CertificateRenewerService(boolean forceRenewal,
        Runnable rotationErrorCallback) {
      this.forceRenewal = forceRenewal;
      this.rotationErrorCallback = rotationErrorCallback;
    }

    @Override
    public void run() {
      // Lock to protect the certificate renew process, to make sure there is
      // only one renew process is ongoing at one time.
      // Certificate renew steps:
      //  1. generate new keys and sign new certificate, persist data to disk
      //  2. switch on disk new keys and certificate with current ones
      //  3. save new certificate ID into service VERSION file
      //  4. refresh in memory certificate ID and reload all new certificates
      synchronized (DefaultCertificateClient.class) {
        X509Certificate currentCert = getCertificate();
        Duration timeLeft = timeBeforeExpiryGracePeriod(currentCert);

        if (!forceRenewal && !timeLeft.isZero()) {
          getLogger().info("Current certificate {} hasn't entered the " +
              "renew grace period. Remaining period is {}. ",
              currentCert.getSerialNumber().toString(), timeLeft);
          return;
        }
        String newCertId;
        try {
          getLogger().info("Current certificate {} needs to be renewed " +
                  "remaining grace period {}. Forced renewal due to root ca " +
                  "rotation: {}.",
              currentCert.getSerialNumber().toString(),
              timeLeft, forceRenewal);
          newCertId = renewAndStoreKeyAndCertificate(forceRenewal);
        } catch (CertificateException e) {
          rotationErrorCallback.run();
          if (e.errorCode() ==
              CertificateException.ErrorCode.ROLLBACK_ERROR) {
            if (shutdownCallback != null) {
              getLogger().error("Failed to rollback key and cert after an " +
                  "unsuccessful renew try.", e);
              shutdownCallback.run();
            }
          }
          getLogger().error("Failed to renew and store key and cert." +
              " Keep using existing certificates.", e);
          return;
        }

        // Persist new cert serial id in component VERSION file
        if (certIdSaveCallback != null) {
          certIdSaveCallback.accept(newCertId);
        }

        // reset and reload all certs
        reloadKeyAndCertificate(newCertId);
        // cleanup backup directory
        cleanBackupDir();
      }
    }
  }

  public void assertValidKeysAndCertificate() throws OzoneSecurityException {
    try {
      Objects.requireNonNull(getPublicKey());
      Objects.requireNonNull(getPrivateKey());
      Objects.requireNonNull(getCertificate());
    } catch (Exception e) {
      throw new OzoneSecurityException("Error reading keypair & certificate", e,
          OM_PUBLIC_PRIVATE_KEY_FILE_NOT_EXIST);
    }
  }
}
