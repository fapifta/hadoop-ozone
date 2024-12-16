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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
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

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.hdds.protocol.proto.SCMSecurityProtocolProtos.SCMGetCertResponseProto;
import org.apache.hadoop.hdds.protocolPB.SCMSecurityProtocolClientSideTranslatorPB;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.exception.OzoneSecurityException;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.certificate.utils.OzoneCertPath;
import org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage;
import org.apache.hadoop.hdds.security.x509.certificate.utils.TrustedCertStorage;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.apache.hadoop.hdds.security.x509.certificate.utils.KeyStorage;

import com.google.common.base.Preconditions;

import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX;
import static org.apache.hadoop.hdds.security.exception.OzoneSecurityException.ResultCodes.OM_PUBLIC_PRIVATE_KEY_FILE_NOT_EXIST;
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

  private final Logger logger;
  private final SecurityConfig securityConfig;
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
    startServices();
  }

  private void startServices() {
    if (shouldStartCertificateRenewerService()) {
      if (securityConfig.isAutoCARotationEnabled()) {
        startRootCaRotationPoller();
      }
      startCertificateRenewerService();
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

  private X509Certificate getCertificate() {
    OzoneCertPath currentCertPath = getCertPath();
    if (currentCertPath == null || currentCertPath.getCertificates() == null) {
      return null;
    }
    return currentCertPath.getLeafCert();
  }

  private synchronized OzoneCertPath getCertPath() {
    if (sslIdentityStorage.getCertPaths().isEmpty()) {
      getLogger().info("No certificates found for certificate client?");
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

      sign.initSign(sslIdentityStorage.getPrivateKey());
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

  protected String getComponentName() {
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
   */
  protected void notifyNotificationReceivers(String newCaCertId) {
    synchronized (notificationReceivers) {
      notificationReceivers.forEach(r -> r.notifyCertificateRenewed(newCaCertId));
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
        OzoneCertPath certPath = getCertPath();
        Preconditions.checkNotNull(certPath);
        Preconditions.checkArgument(
            timeBeforeExpiryGracePeriod(certPath.getLeafCert())
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
      String encodedCert = signCertificate(csrBuilder.build());
      // Return the default certificate ID
      newCertSerialId = sslIdentityStorage.storeCertificate(encodedCert, CAType.NONE, certificatePath);
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
    updateCertSerialId(newCertId);
    getLogger().info("Reset and reloaded key and all certificates for new certificate {}.", newCertId);
    notifyNotificationReceivers(newCertId);
  }

  protected SecurityConfig getSecurityConfig() {
    return securityConfig;
  }

  private synchronized void updateCertSerialId(String newCertSerialId) {
    getLogger().info("Current certificate ID is updated from to {}", newCertSerialId);
    sslIdentityStorage.setCertId(newCertSerialId);
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
    List<String> rootCAPems = getAllRootCaCertificates();
    for (String rootCAPem : rootCAPems) {
      trustedCertStorage.storeCertificate(rootCAPem, CAType.ROOT, certificatePath);
    }
  }

  @Override
  public List<String> getAllRootCaCertificates() throws IOException {
    List<String> rootCAPems = scmSecurityClient.getAllRootCaCertificates();
    return rootCAPems;
  }

  public SCMSecurityProtocolClientSideTranslatorPB getScmSecureClient() {
    return scmSecurityClient;
  }

  protected TrustedCertStorage getTrustedCertStorage() {
    return trustedCertStorage;
  }

  protected SSLIdentityStorage getSslIdentityStorage() {
    return sslIdentityStorage;
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
            true, rootCaRotationPoller::setCertificateRenewalError, false);
    return CompletableFuture.runAsync(renewerService, executorService);
  }

  public synchronized void startCertificateRenewerService() {
    // Schedule task to refresh certificate before it expires
    if (executorService == null) {
      executorService = Executors.newScheduledThreadPool(1,
          new ThreadFactoryBuilder()
              .setNameFormat(threadNamePrefix + getComponentName()
                  + "-CertificateRenewerService")
              .setDaemon(true).build());
    }
    executorService.schedule(new CertificateRenewerService(false, () -> {
    }, true), 1000, TimeUnit.MILLISECONDS);
    getLogger().info("Scheduling CertificateRenewerService to run in 1 s");
  }

  /**
   * Task to monitor certificate lifetime and renew the certificate if needed.
   */
  public class CertificateRenewerService implements Runnable {
    private boolean forceRenewal;
    private Runnable rotationErrorCallback;
    private boolean isReschedule;
    private long waitForInit = 1;

    public CertificateRenewerService(boolean forceRenewal,
        Runnable rotationErrorCallback, boolean isReschedule) {
      this.forceRenewal = forceRenewal;
      this.rotationErrorCallback = rotationErrorCallback;
      this.isReschedule = isReschedule;
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
        if (currentCert == null) {
          getLogger().info("Current certificate is not initialized yet. Returning from CertificateRenewalService.");
          reScheduleIfNeeded();
          return;
        }
        Duration timeLeft = timeBeforeExpiryGracePeriod(currentCert);

        if (!forceRenewal && !timeLeft.isZero()) {
          getLogger().info("Current certificate {} hasn't entered the " +
                  "renew grace period. Remaining period is {}. ",
              currentCert.getSerialNumber().toString(), timeLeft);
          reScheduleIfNeeded();
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
          reScheduleIfNeeded();
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
        reScheduleIfNeeded();
      }
    }

    private void reScheduleIfNeeded() {
      if (!isReschedule) {
        return;
      }
      X509Certificate certificate = getCertificate();
      long delay = getScheduleDelay(certificate);
      synchronized (DefaultCertificateClient.this) {
        executorService.schedule(new CertificateRenewerService(forceRenewal, rotationErrorCallback, isReschedule),
            delay, TimeUnit.MILLISECONDS);
      }
      getLogger().info("CertificateRenewerService is rescheduled in {} ms", delay);
    }

    private long getScheduleDelay(X509Certificate certificate) {
      if (certificate == null) {
        return TimeUnit.SECONDS.toMillis(waitForInit);
      }
      long delay = timeBeforeExpiryGracePeriod(certificate).toMillis();
      // if we are already in grace duration, then reschedule this task to run again in the grace duration
      if (delay <= 0) {
        Duration gracePeriod = securityConfig.getRenewalGracePeriod();
        return Math.min(gracePeriod.toMillis() / 4, TimeUnit.DAYS.toMillis(1));
      }
      // The Java mills resolution is 1ms, add 1ms to avoid task scheduled
      // ahead of time.
      return delay + 1;
    }
  }

  public void assertValidKeysAndCertificate() throws OzoneSecurityException {
    try {
      Objects.requireNonNull(sslIdentityStorage.getPublicKey());
      Objects.requireNonNull(sslIdentityStorage.getPrivateKey());
      Objects.requireNonNull(getCertificate());
    } catch (Exception e) {
      throw new OzoneSecurityException("Error reading keypair & certificate", e,
          OM_PUBLIC_PRIVATE_KEY_FILE_NOT_EXIST);
    }
  }
}
