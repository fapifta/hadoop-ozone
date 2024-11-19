/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership.  The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.hdds.security.x509.certificate.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.hdds.conf.ConfigurationSource;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.security.exception.OzoneSecurityException;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.authority.DefaultApprover;
import org.apache.hadoop.hdds.security.x509.certificate.authority.profile.DefaultProfile;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage;
import org.apache.hadoop.hdds.security.x509.certificate.utils.SelfSignedCertificate;
import org.apache.hadoop.hdds.security.x509.certificate.utils.TrustedCertStorage;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.mockito.Mockito;

import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_X509_DEFAULT_DURATION;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_X509_DEFAULT_DURATION_DEFAULT;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_X509_MAX_DURATION;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_X509_MAX_DURATION_DEFAULT;
import static org.apache.hadoop.hdds.HddsConfigKeys.OZONE_METADATA_DIRS;
import static org.apache.hadoop.hdds.security.exception.OzoneSecurityException.ResultCodes.OM_PUBLIC_PRIVATE_KEY_FILE_NOT_EXIST;
import static org.apache.hadoop.hdds.security.x509.exception.CertificateException.ErrorCode.CRYPTO_SIGNATURE_VERIFICATION_ERROR;

/**
 * Test implementation for CertificateClient. To be used only for test
 * purposes.
 */

public class CertificateClientTestImpl implements CertificateClient {

  private final SecurityConfig securityConfig;
  private final ConfigurationSource configurationSource;
  private KeyPair keyPair;
  private X509Certificate x509Certificate;
  private KeyPair rootKeyPair;
  private X509Certificate rootCert;
  private Set<X509Certificate> rootCerts;

  private HDDSKeyGenerator keyGen;
  private DefaultApprover approver;
  private Map<String, X509Certificate> certificateMap;
  private ScheduledExecutorService executorService;
  private Set<CertificateNotification> notificationReceivers;
  private TrustedCertStorage certificateStorage;
  private SSLIdentityStorage sslIdentityStorage;

  public CertificateClientTestImpl(OzoneConfiguration conf)
      throws Exception {
    this(conf, false);
  }

  public CertificateClientTestImpl(OzoneConfiguration conf, boolean autoRenew)
      throws Exception {
    this.configurationSource = conf;
    certificateMap = new ConcurrentHashMap<>();
    securityConfig = new SecurityConfig(conf);
    rootCerts = new HashSet<>();
    keyGen = new HDDSKeyGenerator(securityConfig);
    keyPair = keyGen.generateKey();
    rootKeyPair = keyGen.generateKey();
    LocalDateTime start = LocalDateTime.now();
    String rootCACertDuration = conf.get(HDDS_X509_MAX_DURATION,
        HDDS_X509_MAX_DURATION_DEFAULT);
    LocalDateTime end = start.plus(Duration.parse(rootCACertDuration));

    // Generate RootCA certificate
    rootCert = SelfSignedCertificate.newBuilder()
        .setBeginDate(start)
        .setEndDate(end)
        .setClusterID("cluster1")
        .setKey(rootKeyPair)
        .setSubject("rootCA@localhost")
        .setConfiguration(securityConfig)
        .setScmID("scm1")
        .makeCA()
        .build();
    certificateMap.put(rootCert.getSerialNumber().toString(), rootCert);
    rootCerts.add(rootCert);

    // Generate normal certificate, signed by RootCA certificate
    approver = new DefaultApprover(new DefaultProfile(), securityConfig);

    CertificateSignRequest.Builder csrBuilder =
        new CertificateSignRequest.Builder();
    // Get host name.
    csrBuilder.setKey(keyPair)
        .setConfiguration(securityConfig)
        .setScmID("scm1")
        .setClusterID("cluster1")
        .setSubject("localhost")
        .setDigitalSignature(true)
        .setDigitalEncryption(true);

    start = LocalDateTime.now();
    String certDuration = conf.get(HDDS_X509_DEFAULT_DURATION,
        HDDS_X509_DEFAULT_DURATION_DEFAULT);
    x509Certificate = approver.sign(securityConfig, rootKeyPair.getPrivate(),
        rootCert,
        Date.from(start.atZone(ZoneId.systemDefault()).toInstant()),
        Date.from(start.plus(Duration.parse(certDuration))
            .atZone(ZoneId.systemDefault()).toInstant()),
        csrBuilder.build().toEncodedFormat(), "scm1", "cluster1",
        String.valueOf(System.nanoTime()));
    certificateMap.put(x509Certificate.getSerialNumber().toString(),
        x509Certificate);

    certificateStorage = Mockito.mock(TrustedCertStorage.class);
    Mockito.when(certificateStorage.getKeyStore()).thenReturn(getKeyStoreForTrustedCertificates(getAllRootCaCerts()));
    if (conf.get(OZONE_METADATA_DIRS) == null) {
      sslIdentityStorage = Mockito.mock(SSLIdentityStorage.class);
      Mockito.when(sslIdentityStorage.getComponentName()).thenReturn(getComponentName());
      Mockito.when(sslIdentityStorage.getKeyStore()).thenReturn(
          getKeyStoreForSSLIdentity(getPrivateKey(), getCertPath()));
    } else {
      FileUtils.deleteDirectory(securityConfig.getKeyLocation(getComponentName()).toFile());
      FileUtils.deleteDirectory(securityConfig.getCertificateLocation(getComponentName()).toFile());
      sslIdentityStorage = new SSLIdentityStorage(securityConfig, getComponentName(),
          x509Certificate.getSerialNumber().toString());
      sslIdentityStorage.storeKeyPair(keyPair);
      sslIdentityStorage.storeCertificate(x509Certificate);
    }

    notificationReceivers = new HashSet<>();

    if (autoRenew) {
      Duration gracePeriod = securityConfig.getRenewalGracePeriod();
      Date expireDate = x509Certificate.getNotAfter();
      LocalDateTime gracePeriodStart = expireDate.toInstant()
          .minus(gracePeriod).atZone(ZoneId.systemDefault()).toLocalDateTime();
      LocalDateTime currentTime = LocalDateTime.now();
      Duration delay = gracePeriodStart.isBefore(currentTime) ? Duration.ZERO :
          Duration.between(currentTime, gracePeriodStart);

      executorService = Executors.newScheduledThreadPool(1,
          new ThreadFactoryBuilder().setNameFormat("CertificateRenewerService")
              .setDaemon(true).build());
      this.executorService.schedule(new RenewCertTask(),
          delay.toMillis(), TimeUnit.MILLISECONDS);
    }
  }

  @Override
  public PrivateKey getPrivateKey() {
    return keyPair.getPrivate();
  }

  @Override
  public PublicKey getPublicKey() {
    return keyPair.getPublic();
  }

  public CertPath getCertPath() {
    CertPath resultPath = null;
    try {
      List<X509Certificate> list = new ArrayList<>();
      list.add(x509Certificate);
      list.add(rootCert);
      resultPath = CertificateFactory.getInstance("X.509").generateCertPath(list);
    } catch (java.security.cert.CertificateException ignored) {

    }
    return resultPath;
  }

  @Override
  public X509Certificate getCertificate() {
    return x509Certificate;
  }

  @Override
  public String getCertSerialId() {
    return x509Certificate.getSerialNumber().toString();
  }

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
      System.out.println("Error while signing the stream " + e.getMessage());
      throw new CertificateException("Error while signing the stream", e,
          CRYPTO_SIGNATURE_VERIFICATION_ERROR);
    }
  }

  @Override
  public CertificateSignRequest.Builder configureCSRBuilder() throws SCMSecurityException {
    return new CertificateSignRequest.Builder();
  }

  @Override
  public void initWithRecovery() throws IOException {
  }

  @Override
  public String getComponentName() {
    return this.getClass().getSimpleName();
  }

  @Override
  public SecurityConfig getSecurityConfig() {
    return securityConfig;
  }

  public X509Certificate getRootCACertificate() {
    return rootCert;
  }

  public Set<X509Certificate> getAllRootCaCerts() {
    return rootCerts;
  }

  public void renewRootCA() throws Exception {
    LocalDateTime start = LocalDateTime.now();
    Duration rootCACertDuration = securityConfig.getMaxCertificateDuration();
    LocalDateTime end = start.plus(rootCACertDuration);
    rootKeyPair = keyGen.generateKey();
    rootCert = SelfSignedCertificate.newBuilder()
        .setBeginDate(start)
        .setEndDate(end)
        .setClusterID("cluster1")
        .setKey(rootKeyPair)
        .setSubject("rootCA-new@localhost")
        .setConfiguration(securityConfig)
        .setScmID("scm1")
        .makeCA(BigInteger.ONE.add(BigInteger.ONE))
        .build();
    certificateMap.put(rootCert.getSerialNumber().toString(), rootCert);
    rootCerts.add(rootCert);
  }

  public void renewKey() throws Exception {
    KeyPair newKeyPair = keyGen.generateKey();
    CertificateSignRequest.Builder csrBuilder =
        new CertificateSignRequest.Builder();
    // Get host name.
    csrBuilder.setKey(newKeyPair)
        .setConfiguration(securityConfig)
        .setScmID("scm1")
        .setClusterID("cluster1")
        .setSubject("localhost")
        .setDigitalSignature(true);

    Duration certDuration = securityConfig.getDefaultCertDuration();
    Date start = new Date();
    X509Certificate newX509Certificate =
        approver.sign(securityConfig, rootKeyPair.getPrivate(), rootCert, start,
            new Date(start.getTime() + certDuration.toMillis()),
            csrBuilder.build().toEncodedFormat(), "scm1", "cluster1",
            String.valueOf(System.nanoTime())
        );

    // Save the new private key and certificate to file
    // Save certificate and private key to keyStore
    X509Certificate oldCert = x509Certificate;
    keyPair = newKeyPair;
    x509Certificate = newX509Certificate;
    certificateMap.put(x509Certificate.getSerialNumber().toString(),
        x509Certificate);
    if (configurationSource.get(OZONE_METADATA_DIRS) == null) {
      Mockito.when(certificateStorage.getKeyStore()).thenReturn(getKeyStoreForTrustedCertificates(getAllRootCaCerts()));
      Mockito.when(sslIdentityStorage.getKeyStore()).thenReturn(
          getKeyStoreForSSLIdentity(getPrivateKey(), getCertPath()));
    } else {
      FileUtils.deleteDirectory(securityConfig.getKeyLocation(getComponentName()).toFile());
      FileUtils.deleteDirectory(securityConfig.getCertificateLocation(getComponentName()).toFile());
      sslIdentityStorage = new SSLIdentityStorage(securityConfig, getComponentName(),
          x509Certificate.getSerialNumber().toString());
      sslIdentityStorage.storeKeyPair(keyPair);
      sslIdentityStorage.storeCertificate(x509Certificate);
    }
    Mockito.when(certificateStorage.getKeyStore()).thenReturn(getKeyStoreForTrustedCertificates(getAllRootCaCerts()));
    // notify notification receivers
    notificationReceivers.forEach(r -> r.notifyCertificateRenewed(
        oldCert.getSerialNumber().toString(),
        x509Certificate.getSerialNumber().toString()));
  }

  /**
   * Task to renew certificate.
   */
  public class RenewCertTask implements Runnable {
    @Override
    public void run() {
      try {
        renewRootCA();
        renewKey();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  public KeyStore getKeyStoreForTrustedCertificates(Set<X509Certificate> newRootCaCerts)
      throws java.security.cert.CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    newRootCaCerts.forEach(certificate -> {
      try {
        keyStore.setCertificateEntry(
            certificate.getSerialNumber().toString(), certificate);
      } catch (KeyStoreException e) {
        throw new RuntimeException(e);
      }
    });
    return keyStore;
  }

  public KeyStore getKeyStoreForSSLIdentity(PrivateKey privateKey, CertPath trustChain)
      throws java.security.cert.CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    insertCertsToKeystore(keyStore, privateKey, trustChain);
    return keyStore;
  }

  private void insertCertsToKeystore(KeyStore keyStore, PrivateKey privateKey, CertPath certPath)
      throws KeyStoreException {
    List<X509Certificate> certsFromPath =
        certPath.getCertificates().stream()
            .map(certificate -> (X509Certificate) certificate)
            .collect(Collectors.toList());
    keyStore.setKeyEntry(certsFromPath.get(0).getSerialNumber().toString(),
        privateKey, "".toCharArray(), certsFromPath.toArray(new X509Certificate[0]));
  }

  @Override
  public void registerNotificationReceiver(CertificateNotification receiver) {
    synchronized (notificationReceivers) {
      notificationReceivers.add(receiver);
    }
  }

  @Override
  public void registerRootCARotationListener(
      Function<List<X509Certificate>, CompletableFuture<Void>> listener) {
    // we do not have tests that rely on rootCA rotation atm, leaving this
    // implementation blank for now.
  }

  @Override
  public void close() throws IOException {
    if (executorService != null) {
      executorService.shutdown();
    }
  }

  @Override
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
