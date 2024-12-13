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

package org.apache.hadoop.hdds.security.x509.certificate.authority;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.authority.profile.DefaultCAProfile;
import org.apache.hadoop.hdds.security.x509.certificate.authority.profile.DefaultProfile;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.certificate.utils.OzoneCertPath;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.apache.hadoop.hdds.HddsConfigKeys.OZONE_METADATA_DIRS;
import static org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType.OM;
import static org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType.SCM;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Tests the common functionality of CA servers.
 * All tests in this class should be parameterized and run on all CAServer implementation.
 */
public class TestCAServerCommon {
  private OzoneConfiguration conf;
  private SecurityConfig securityConfig;
  private static MockCAStore caStore;
  private CertificateServer certServer;
  private static File testDir;

  @BeforeEach
  public void init() throws IOException {
    conf = new OzoneConfiguration();
    conf.set(OZONE_METADATA_DIRS, testDir.toString());
    securityConfig = new SecurityConfig(conf);
  }

  @BeforeAll
  public static void initPath() throws IOException {
    testDir = Files.createTempDirectory(Paths.get(""), "test_dir").toFile();
    testDir.deleteOnExit();
  }

  @AfterAll
  public static void clearPath() throws IOException {
    FileUtils.deleteDirectory(testDir);
    testDir.deleteOnExit();
  }

  @ParameterizedTest
  @MethodSource("createCertServer")
  public void testInitParameterized(CertificateServer certificateServer) throws Exception {
    this.certServer = certificateServer;
    certServer.init(securityConfig);
    X509Certificate first = certServer.getCaCertPath().getLeafCert();
    assertNotNull(first);
    //Init is idempotent.
    certServer.init(securityConfig);
    X509Certificate second = certServer.getCaCertPath().getLeafCert();
    assertEquals(first.getSerialNumber(), second.getSerialNumber());
  }

  @ParameterizedTest
  @MethodSource("createCertServer")
  public void testMissingCertificate(CertificateServer certificateServer) throws IOException {
    this.certServer = certificateServer;
    File rootCADir = Paths.get(testDir.toString(), "scm", "ca", "certs").toFile();
    File subCADir = Paths.get(testDir.toString(), "scm", "sub-ca", "certs").toFile();
    tempDeleteDirectory(rootCADir);
    tempDeleteDirectory(subCADir);

    RuntimeException e =
        assertThrows(RuntimeException.class, () -> certServer.init(securityConfig));
    assertThat(e.toString()).contains("Missing CA Certs");
    restoreDirectory(rootCADir);
    restoreDirectory(subCADir);
  }

  private static void tempDeleteDirectory(File directory) throws IOException {
    if (directory.exists()) {
      FileUtils.moveDirectory(directory, Paths.get(testDir.toString(), "tmp", directory.toString()).toFile());
    }
  }

  private static void restoreDirectory(File directory) throws IOException {
    FileUtils.moveDirectory(Paths.get(testDir.toString(), "tmp", directory.toString()).toFile(), directory);
  }

  @ParameterizedTest
  @MethodSource("createCertServer")
  public void testMissingKey(CertificateServer certificateServer) throws IOException {
    this.certServer = certificateServer;
    File rootCAServerKeysDir = Paths.get(testDir.toString(), "scm", "ca", "keys").toFile();
    File subCAServerKeysDir = Paths.get(testDir.toString(), "scm", "sub-ca", "keys").toFile();
    tempDeleteDirectory(rootCAServerKeysDir);
    tempDeleteDirectory(subCAServerKeysDir);
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> certServer.init(securityConfig));
    // This also is a runtime exception. Hence, not caught by junit expected exception.
    assertThat(e.toString()).contains("Missing Keys");
    restoreDirectory(rootCAServerKeysDir);
    restoreDirectory(subCAServerKeysDir);
  }


  private static Stream<Arguments> createCertServer() throws IOException {
    caStore = new MockCAStore();
    OzoneConfiguration configuration = new OzoneConfiguration();
    configuration.set(OZONE_METADATA_DIRS, testDir.toString());
    SecurityConfig secConf = new SecurityConfig(configuration);
    String clusterId = RandomStringUtils.randomAlphabetic(4);
    String scmId = RandomStringUtils.randomAlphabetic(4);
    RootCAServer rootCAServer = new RootCAServer("testCA",
        clusterId, scmId, caStore,
        new DefaultCAProfile(),
        BigInteger.ONE, t -> {
    });
    rootCAServer.init(secConf);
    SubCAServer subCAServer =
        new SubCAServer("testCA", clusterId, scmId, caStore, new DefaultProfile(), t -> {
        }, "testhost", rootCAServer);
    subCAServer.init(secConf);
    return Stream.of(
        Arguments.of(Named.of("RootCAServer as cert server", rootCAServer)),
        Arguments.of(Named.of("SubCAServer as cert server", subCAServer))
    );
  }

  /**
   * The most important test of this test suite. This tests that we are able
   * to create a Test CA, creates it own self-Signed CA and then issue a
   * certificate based on a CSR.
   *
   * @throws SCMSecurityException     - on ERROR.
   * @throws ExecutionException       - on ERROR.
   * @throws InterruptedException     - on ERROR.
   * @throws NoSuchProviderException  - on ERROR.
   * @throws NoSuchAlgorithmException - on ERROR.
   */
  @ParameterizedTest
  @MethodSource("createCertServer")
  public void testRequestCertificate(DefaultCAServer certificateServer) throws Exception {
    KeyPair keyPair =
        new HDDSKeyGenerator(securityConfig).generateKey();
    certificateServer.init(securityConfig);

    CertificateSignRequest csr = new CertificateSignRequest.Builder()
        .addDnsName("hadoop.apache.org")
        .addIpAddress("8.8.8.8")
        .addServiceName("OzoneMarketingCluster002")
        .setCA(false)
        .setClusterID(certificateServer.getClusterID())
        .setScmID(certificateServer.getScmID())
        .setSubject("Ozone Cluster")
        .setConfiguration(securityConfig)
        .setKey(keyPair)
        .build();

    Future<OzoneCertPath> holder = certificateServer.requestCertificate(
        csr.toEncodedFormat(), CertificateApprover.ApprovalType.TESTING_AUTOMATIC, SCM,
        String.valueOf(System.nanoTime()));
    //Test that the cert path returned contains the CA certificate in proper
    // place
    List<? extends Certificate> certBundle = holder.get().getCertificates();
    X509Certificate caInReturnedBundle = (X509Certificate) certBundle.get(1);
    assertEquals(caInReturnedBundle, certificateServer.getCaCertPath().getLeafCert());
    X509Certificate signedCert = holder.get().getLeafCert();
    //Test that the ca has signed of the returned certificate
    assertEquals(caInReturnedBundle.getSubjectX500Principal(), signedCert.getIssuerX500Principal());
  }

  /**
   * Tests that we are able
   * to create a Test CA, creates it own self-Signed CA and then issue a
   * certificate based on a CSR when scmId and clusterId are not set in
   * csr subject.
   *
   * @throws SCMSecurityException     - on ERROR.
   * @throws ExecutionException       - on ERROR.
   * @throws InterruptedException     - on ERROR.
   * @throws NoSuchProviderException  - on ERROR.
   * @throws NoSuchAlgorithmException - on ERROR.
   */
  @ParameterizedTest
  @MethodSource("createCertServer")
  public void testRequestCertificateWithInvalidSubject(CertificateServer certificateServer) throws Exception {
    KeyPair keyPair =
        new HDDSKeyGenerator(securityConfig).generateKey();
    CertificateSignRequest csr = new CertificateSignRequest.Builder()
        .addDnsName("hadoop.apache.org")
        .addIpAddress("8.8.8.8")
        .setCA(false)
        .setSubject("Ozone Cluster")
        .setConfiguration(securityConfig)
        .setKey(keyPair)
        .build();

    certificateServer.init(securityConfig);

    Future<OzoneCertPath> holder = certificateServer.requestCertificate(
        csr.toEncodedFormat(), CertificateApprover.ApprovalType.TESTING_AUTOMATIC, OM,
        String.valueOf(System.nanoTime()));
    // Right now our calls are synchronous. Eventually this will have to wait.
    assertTrue(holder.isDone());
    assertNotNull(holder.get().getLeafCert());
  }

  @ParameterizedTest
  @MethodSource("createCertServer")
  public void testRequestCertificateWithInvalidSubjectFailure(CertificateServer certificateServer) throws Exception {
    KeyPair keyPair =
        new HDDSKeyGenerator(securityConfig).generateKey();
    CertificateSignRequest csr = new CertificateSignRequest.Builder()
        .addDnsName("hadoop.apache.org")
        .addIpAddress("8.8.8.8")
        .setCA(false)
        .setScmID("wrong one")
        .setClusterID("223432rf")
        .setSubject("Ozone Cluster")
        .setConfiguration(securityConfig)
        .setKey(keyPair)
        .build();

    certificateServer.init(securityConfig);

    ExecutionException execution = assertThrows(ExecutionException.class,
        () -> {
          Future<OzoneCertPath> holder =
              certificateServer.requestCertificate(csr.toEncodedFormat(),
                  CertificateApprover.ApprovalType.TESTING_AUTOMATIC, OM,
                  String.valueOf(System.nanoTime()));
          holder.get();
        });
    assertThat(execution.getCause().getMessage())
        .contains("ScmId and ClusterId in CSR subject are incorrect");
  }
}
