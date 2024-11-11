/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hdds.security.x509.certificate.client;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.hadoop.hdds.HddsUtils;
import org.apache.hadoop.hdds.protocol.proto.SCMSecurityProtocolProtos.SCMGetCertResponseProto;
import org.apache.hadoop.hdds.protocolPB.SCMSecurityProtocolClientSideTranslatorPB;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.protocol.proto.HddsProtos;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateCodec;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage;
import org.apache.hadoop.hdds.security.x509.certificate.utils.TrustedCertStorage;
import org.apache.hadoop.ozone.OzoneConsts;
import org.apache.hadoop.ozone.OzoneSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import static org.apache.hadoop.ozone.OzoneConsts.SCM_SUB_CA_PREFIX;

/**
 * SCM Certificate Client which is used for generating public/private Key pair,
 * generate CSR and finally obtain signed certificate. This Certificate
 * client is used for setting up sub CA by SCM.
 */
public class SCMCertificateClient extends DefaultCertificateClient {

  private static final Logger LOG =
      LoggerFactory.getLogger(SCMCertificateClient.class);

  public static final String COMPONENT_NAME =
      Paths.get(OzoneConsts.SCM_CA_CERT_STORAGE_DIR,
          OzoneConsts.SCM_SUB_CA_PATH).toString();
  private String scmId;
  private String cId;
  private String scmHostname;
  private ExecutorService executorService;

  @SuppressWarnings("checkstyle:ParameterNumber")
  public SCMCertificateClient(SecurityConfig securityConfig,
      SCMSecurityProtocolClientSideTranslatorPB scmClient,
      String scmId, String clusterId, String scmCertId, String hostname, SSLIdentityStorage sslIdentityStorage,
      TrustedCertStorage trustedCertStorage) {
    this(securityConfig, scmClient, scmId, clusterId, scmCertId, hostname,
        COMPONENT_NAME, sslIdentityStorage, trustedCertStorage);
  }

  @SuppressWarnings("checkstyle:ParameterNumber")
  private SCMCertificateClient(SecurityConfig securityConfig,
      SCMSecurityProtocolClientSideTranslatorPB scmClient,
      String scmId, String clusterId, String scmCertId, String hostname,
      String component, SSLIdentityStorage sslIdentityStorage, TrustedCertStorage trustedCertStorage) {
    super(securityConfig, scmClient, LOG, scmCertId, component,
        HddsUtils.threadNamePrefix(scmId), null, null, sslIdentityStorage, trustedCertStorage);
    this.scmId = scmId;
    this.cId = clusterId;
    this.scmHostname = hostname;
  }

  public SCMCertificateClient(
      SecurityConfig securityConfig,
      SCMSecurityProtocolClientSideTranslatorPB scmClient,
      String certSerialId,
      String scmId,
      String component, SSLIdentityStorage sslIdentityStorage, TrustedCertStorage trustedCertStorage) {
    this(securityConfig, scmClient, scmId, null, certSerialId, null, component, sslIdentityStorage, trustedCertStorage);
  }

  /**
   * Returns a CSR builder that can be used to creates a Certificate signing
   * request.
   *
   * @return CertificateSignRequest.Builder
   */
  public CertificateSignRequest.Builder configureCSRBuilder()
      throws SCMSecurityException {
    String subject = SCM_SUB_CA_PREFIX + scmHostname;

    LOG.info("Creating csr for SCM->hostName:{},scmId:{},clusterId:{}," +
        "subject:{}", scmHostname, scmId, cId, subject);

    return super.configureCSRBuilder()
        .setSubject(subject)
        .setScmID(scmId)
        .setClusterID(cId)
        // Set CA to true, as this will be used to sign certs for OM/DN.
        .setCA(true)
        .setKey(new KeyPair(getPublicKey(), getPrivateKey()));
  }

  @Override
  protected boolean shouldStartCertificateRenewerService() {
    return false;
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  @Override
  protected SCMGetCertResponseProto sign(CertificateSignRequest csr) throws IOException {
    HddsProtos.ScmNodeDetailsProto scmNodeDetailsProto =
        HddsProtos.ScmNodeDetailsProto.newBuilder()
            .setClusterId(cId)
            .setHostName(scmHostname)
            .setScmNodeId(scmId).build();
    return getScmSecureClient().getSCMCertChain(scmNodeDetailsProto, csr.toEncodedFormat(), true);
  }

  public void refreshCACertificates() throws IOException {
    if (executorService == null) {
      executorService = Executors.newSingleThreadExecutor(
          new ThreadFactoryBuilder()
              .setNameFormat(threadNamePrefix() + getComponentName()
                  + "-refreshCACertificates")
              .setDaemon(true).build());
    }
    executorService.execute(new RefreshCACertificates(getScmSecureClient()));
  }

  /**
   * Task to refresh root CA certificates for SCM.
   */
  public class RefreshCACertificates implements Runnable {
    private final SCMSecurityProtocolClientSideTranslatorPB scmSecureClient;

    public RefreshCACertificates(
        SCMSecurityProtocolClientSideTranslatorPB client) {
      this.scmSecureClient = client;
    }

    @Override
    public void run() {
      try {
        // In case root CA certificate is rotated during this SCM is offline
        // period, fetch the new root CA list from leader SCM and refresh ratis
        // server's tlsConfig.
        List<String> rootCAPems = scmSecureClient.getAllRootCaCertificates();

        // SCM certificate client currently sets root CA as CA cert
        Set<X509Certificate> certList = getTrustedCertStorage().getLeafCertificates();
        List<X509Certificate> rootCAsFromLeaderSCM =
            OzoneSecurityUtil.convertToX509(rootCAPems);
        rootCAsFromLeaderSCM.removeAll(certList);

        if (rootCAsFromLeaderSCM.isEmpty()) {
          LOG.info("CA certificates are not changed.");
          return;
        }

        for (X509Certificate cert : rootCAsFromLeaderSCM) {
          LOG.info("Fetched new root CA certificate {} from leader SCM",
              cert.getSerialNumber().toString());
          getTrustedCertStorage().storeCertificate(
              CertificateCodec.encode(cert), CAType.SUBORDINATE,
              getSecurityConfig().getCertificateLocation(getComponentName()));
        }
        String scmCertId = getCertSerialId();
        notifyNotificationReceivers(scmCertId, scmCertId);
      } catch (IOException e) {
        LOG.error("Failed to refresh CA certificates", e);
      }
    }
  }

  @Override
  public synchronized void close() throws IOException {
    super.close();
    if (executorService != null) {
      executorService.shutdownNow();
      executorService = null;
    }
  }
}
