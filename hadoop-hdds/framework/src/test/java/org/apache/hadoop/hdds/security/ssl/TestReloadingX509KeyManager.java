/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdds.security.ssl;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClientTestImpl;
import org.apache.hadoop.hdds.security.x509.certificate.utils.SSLIdentityStorage;
import org.apache.ozone.test.GenericTestUtils.LogCapturer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Test ReloadingX509KeyManager.
 */
public class TestReloadingX509KeyManager {
  private final LogCapturer reloaderLog =
      LogCapturer.captureLogs(ReloadingX509KeyManager.LOG);
  private static OzoneConfiguration conf;
  private static CertificateClientTestImpl caClient;
  private static SSLIdentityStorage sslIdentityStorage;

  @BeforeAll
  public static void setUp() throws Exception {
    conf = new OzoneConfiguration();
    caClient = new CertificateClientTestImpl(conf);
    sslIdentityStorage = Mockito.mock(SSLIdentityStorage.class);
    Mockito.when(sslIdentityStorage.getKeyStore()).thenReturn(
        caClient.getKeyStoreForSSLIdentity(caClient.getPrivateKey(), caClient.getCertPath()));
  }

  @Test
  public void testReload() throws Exception {
    ReloadingX509KeyManager km = new ReloadingX509KeyManager(sslIdentityStorage);
    PrivateKey privateKey1 = caClient.getPrivateKey();
    assertEquals(privateKey1, km.getPrivateKey(caClient.getCertificate().getSerialNumber().toString()));

    caClient.renewRootCA();
    caClient.renewKey();
    Mockito.when(sslIdentityStorage.getKeyStore()).thenReturn(
        caClient.getKeyStoreForSSLIdentity(caClient.getPrivateKey(), caClient.getCertPath()));
    km.notifyCertificateRenewed(caClient.getCertSerialId());
    PrivateKey privateKey2 = caClient.getPrivateKey();
    assertNotEquals(privateKey1, privateKey2);

    assertEquals(privateKey2, km.getPrivateKey(caClient.getCertificate().getSerialNumber().toString()));

    assertThat(reloaderLog.getOutput()).contains("ReloadingX509KeyManager is reloaded");

    // Only one reload has to happen for the CertificateClient's keyManager.
    assertEquals(1, StringUtils.countMatches(reloaderLog.getOutput(), "ReloadingX509KeyManager is reloaded"));
  }
}
