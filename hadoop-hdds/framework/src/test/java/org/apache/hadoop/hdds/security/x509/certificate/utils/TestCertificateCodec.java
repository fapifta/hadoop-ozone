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

import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import static org.apache.hadoop.hdds.HddsConfigKeys.OZONE_METADATA_DIRS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the Certificate codecs.
 */
public class TestCertificateCodec {
  private SecurityConfig securityConfig;
  public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
  public static final String END_CERT = "-----END CERTIFICATE-----";

  @BeforeEach
  public void init(@TempDir Path tempDir) {
    OzoneConfiguration conf = new OzoneConfiguration();
    conf.set(OZONE_METADATA_DIRS, tempDir.toString());
    securityConfig = new SecurityConfig(conf);
  }

  /**
   * This test converts a X509Certificate Holder object to a PEM encoded String,
   * then creates a new X509Certificate object to verify that we are able to
   * serialize and deserialize correctly. we follow up with converting these
   * objects to standard JCA x509Certificate objects.
   */
  @Test
  public void testGetPEMEncodedString() throws Exception {
    X509Certificate cert = generateTestCert();
    String pemString = CertificateCodec.get().encode(cert);
    assertTrue(pemString.startsWith(BEGIN_CERT));
    assertTrue(pemString.endsWith(END_CERT + "\n"));

    // Read back the certificate and verify that all the comparisons pass.
    X509Certificate newCert = CertificateCodec.get().decode(pemString).getLeafCert();
    assertEquals(cert, newCert);
  }

  /**
   * Test when converting a certificate path to pem encoded string and back
   * we get back the same certificates.
   */
  @Test
  public void testGetPemEncodedStringFromCertPath() throws Exception {
    X509Certificate cert1 = generateTestCert();
    X509Certificate cert2 = generateTestCert();
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

    CertPath pathToEncode = certificateFactory.generateCertPath(ImmutableList.of(cert1, cert2));
    String encodedPath = CertificateCodec.get().encode((pathToEncode));
    OzoneCertPath certPathDecoded = CertificateCodec.get().decode(encodedPath);

    assertEquals(cert1, certPathDecoded.getLeafCert());
    assertEquals(cert2, certPathDecoded.getCertificates().get(1));
  }

  private X509Certificate generateTestCert() throws Exception {
    HDDSKeyGenerator keyGenerator =
        new HDDSKeyGenerator(securityConfig);
    LocalDateTime startDate = LocalDateTime.now();
    LocalDateTime endDate = startDate.plusDays(1);
    return SelfSignedCertificate.newBuilder()
        .setSubject(RandomStringUtils.randomAlphabetic(4))
        .setClusterID(RandomStringUtils.randomAlphabetic(4))
        .setScmID(RandomStringUtils.randomAlphabetic(4))
        .setBeginDate(startDate)
        .setEndDate(endDate)
        .setConfiguration(securityConfig)
        .setKey(keyGenerator.generateKey())
        .makeCA()
        .build();
  }

}
