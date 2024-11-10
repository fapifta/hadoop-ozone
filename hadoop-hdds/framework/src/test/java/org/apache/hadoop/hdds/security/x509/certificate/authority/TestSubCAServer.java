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

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hadoop.hdds.HddsConfigKeys;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.protocol.proto.SCMSecurityProtocolProtos;
import org.apache.hadoop.hdds.protocolPB.SCMSecurityProtocolClientSideTranslatorPB;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.authority.profile.DefaultProfile;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateCodec;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateSignRequest;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.concurrent.Future;

import static org.apache.hadoop.hdds.HddsConfigKeys.OZONE_METADATA_DIRS;
import static org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType.SCM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the RootCAServer's additional functionality to DefaultCAServer.
 */
public class TestSubCAServer {


  private OzoneConfiguration conf;
  private SecurityConfig securityConfig;
  private MockCAStore caStore;
  private Path testDir;

  @BeforeEach
  public void init(@TempDir Path dir) throws IOException {
    conf = new OzoneConfiguration();
    testDir = dir;
    conf.set(OZONE_METADATA_DIRS, testDir.toString());
    securityConfig = new SecurityConfig(conf);
    caStore = new MockCAStore();
  }

  @Test
  public void testIntermediaryCAWithEmpty() {
    CertificateServer scmCA = new SubCAServer("testCA",
        RandomStringUtils.randomAlphabetic(4),
        RandomStringUtils.randomAlphabetic(4), caStore,
        new DefaultProfile(), null, "host");

    assertThrows(IllegalStateException.class,
        () -> scmCA.init(securityConfig));
  }

  @Test
  void testCertSignedByNonPrimarySCM() throws Exception {
    conf.set(HddsConfigKeys.HDDS_X509_MAX_DURATION, "P3650D");
    securityConfig = new SecurityConfig(conf);

    String clusterId = RandomStringUtils.randomAlphanumeric(4);
    String scmId = RandomStringUtils.randomAlphanumeric(4);

    CertificateServer rootCA = new RootCAServer("rootCA",
        clusterId, scmId, caStore, new DefaultProfile(), BigInteger.ONE, null);

    rootCA.init(securityConfig);

    // Generate cert
    KeyPair keyPair =
        new HDDSKeyGenerator(securityConfig).generateKey();
    CertificateSignRequest csr = new CertificateSignRequest.Builder()
        .addDnsName("hadoop.apache.org")
        .addIpAddress("8.8.8.8")
        .setCA(false)
        .setSubject("testCA")
        .setConfiguration(securityConfig)
        .setKey(keyPair)
        .build();

    Future<CertPath> holder = rootCA.requestCertificate(csr.toEncodedFormat(),
        CertificateApprover.ApprovalType.TESTING_AUTOMATIC, SCM,
        String.valueOf(System.nanoTime()));
    assertTrue(holder.isDone());
    X509Certificate certificate = (X509Certificate) holder.get().getCertificates().get(0);

    assertNotNull(certificate);
    LocalDate invalidAfterDate = certificate.getNotAfter().toInstant()
        .atZone(ZoneId.systemDefault())
        .toLocalDate();
    LocalDate now = LocalDate.now();
    assertEquals(0, invalidAfterDate.compareTo(now.plusDays(3650)));

    X509Certificate caCertificate = (X509Certificate) rootCA.getCaCertPath().getCertificates().get(0);

    // The certificate generated by above cert client will be used by scmCA.
    // Now scmCA init should be successful.
    SCMSecurityProtocolClientSideTranslatorPB translatorPB =
        Mockito.mock(SCMSecurityProtocolClientSideTranslatorPB.class);
    SCMSecurityProtocolProtos.SCMGetCertResponseProto mockResponse =
        SCMSecurityProtocolProtos.SCMGetCertResponseProto
            .newBuilder()
            .setResponseCode(SCMSecurityProtocolProtos.SCMGetCertResponseProto.ResponseCode.success)
            .setX509Certificate(CertificateCodec.getPEMEncodedString(certificate))
            .setX509CACertificate(CertificateCodec.getPEMEncodedString(caCertificate))
            .setX509RootCACertificate(CertificateCodec.getPEMEncodedString(caCertificate))
            .build();
    Mockito.when(translatorPB.getSCMCertChain(Mockito.any(), Mockito.any(), Mockito.anyBoolean()))
        .thenReturn(mockResponse);
    CertificateServer scmCA = new SubCAServer(
        "scmCA", clusterId, scmId, caStore, new DefaultProfile(), t -> {
    }, "scm", translatorPB);
    scmCA.init(securityConfig);
    assertEquals(scmCA.getCaCertPath().getCertificates().get(0), certificate);
  }

}
