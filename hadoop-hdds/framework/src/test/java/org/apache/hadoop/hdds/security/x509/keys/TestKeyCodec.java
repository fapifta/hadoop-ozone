/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
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

package org.apache.hadoop.hdds.security.x509.keys;

import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_METADATA_DIR_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.utils.KeyStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Test class for HDDS pem writer.
 */
public class TestKeyCodec {

  private SecurityConfig securityConfig;
  private String component;
  private HDDSKeyGenerator keyGenerator;
  private String prefix;

  @BeforeEach
  public void init(@TempDir Path tempDir) throws IOException {
    OzoneConfiguration configuration = new OzoneConfiguration();
    prefix = tempDir.toString();
    configuration.set(HDDS_METADATA_DIR_NAME, prefix);
    securityConfig = new SecurityConfig(configuration);
    keyGenerator = new HDDSKeyGenerator(securityConfig);
    component = "test_component";
  }

  /**
   * Assert basic things like we are able to create a file, and the names are
   * in expected format etc.
   *
   * @throws NoSuchProviderException - On Error, due to missing Java
   * dependencies.
   * @throws NoSuchAlgorithmException - On Error,  due to missing Java
   * dependencies.
   * @throws IOException - On I/O failure.
   */
  @Test
  public void testWriteKey()
      throws NoSuchProviderException, NoSuchAlgorithmException,
      IOException, InvalidKeySpecException {
    KeyPair keys = keyGenerator.generateKey();
    KeyStorage keyStorage = new KeyStorage(securityConfig, component);
    keyStorage.storeKey(keys);

    // Assert that locations have been created.
    Path keyLocation = securityConfig.getKeyLocation(component);
    assertTrue(keyLocation.toFile().exists());

    // Assert that locations are created in the locations that we specified
    // using the Config.
    assertTrue(keyLocation.toString().startsWith(prefix));
    Path privateKeyPath = Paths.get(keyLocation.toString(),
        securityConfig.getPrivateKeyFileName());
    assertTrue(privateKeyPath.toFile().exists());
    Path publicKeyPath = Paths.get(keyLocation.toString(),
        securityConfig.getPublicKeyFileName());
    assertTrue(publicKeyPath.toFile().exists());

    // Read the private key and test if the expected String in the PEM file
    // format exists.
    byte[] privateKey = Files.readAllBytes(privateKeyPath);
    String privateKeydata = new String(privateKey, StandardCharsets.UTF_8);
    assertThat(privateKeydata).contains("PRIVATE KEY");

    // Read the public key and test if the expected String in the PEM file
    // format exists.
    byte[] publicKey = Files.readAllBytes(publicKeyPath);
    String publicKeydata = new String(publicKey, StandardCharsets.UTF_8);
    assertThat(publicKeydata).contains("PUBLIC KEY");

    // Let us decode the PEM file and parse it back into binary.
    KeyFactory kf = KeyFactory.getInstance(securityConfig.getKeyAlgo());

    // Replace the PEM Human readable guards.
    privateKeydata =
        privateKeydata.replace("-----BEGIN PRIVATE KEY-----\n", "");
    privateKeydata =
        privateKeydata.replace("-----END PRIVATE KEY-----", "");

    // Decode the bas64 to binary format and then use an ASN.1 parser to
    // parse the binary format.

    byte[] keyBytes = Base64.decodeBase64(privateKeydata);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    PrivateKey privateKeyDecoded = kf.generatePrivate(spec);
    assertNotNull(privateKeyDecoded,
        "Private Key should not be null");

    // Let us decode the public key and veriy that we can parse it back into
    // binary.
    publicKeydata =
        publicKeydata.replace("-----BEGIN PUBLIC KEY-----\n", "");
    publicKeydata =
        publicKeydata.replace("-----END PUBLIC KEY-----", "");

    keyBytes = Base64.decodeBase64(publicKeydata);
    X509EncodedKeySpec pubKeyspec = new X509EncodedKeySpec(keyBytes);
    PublicKey publicKeyDecoded = kf.generatePublic(pubKeyspec);
    assertNotNull(publicKeyDecoded, "Public Key should not be null");

    // Now let us assert the permissions on the Directories and files are as
    // expected.
    Set<PosixFilePermission> expectedSet = KeyStorage.FILE_PERMISSION_SET;
    Set<PosixFilePermission> currentSet =
        Files.getPosixFilePermissions(privateKeyPath);
    assertEquals(expectedSet.size(), currentSet.size());
    currentSet.removeAll(expectedSet);
    assertEquals(0, currentSet.size());

    currentSet =
        Files.getPosixFilePermissions(publicKeyPath);
    currentSet.removeAll(expectedSet);
    assertEquals(0, currentSet.size());

    expectedSet = KeyStorage.DIR_PERMISSION_SET;
    currentSet =
        Files.getPosixFilePermissions(keyLocation);
    assertEquals(expectedSet.size(), currentSet.size());
    currentSet.removeAll(expectedSet);
    assertEquals(0, currentSet.size());
  }

  /**
   * Assert key rewrite fails without force option.
   *
   * @throws IOException - on I/O failure.
   */
  @Test
  public void testReWriteKey()
      throws Exception {
    KeyPair kp = keyGenerator.generateKey();
    KeyStorage keyStorage = new KeyStorage(this.securityConfig, component);
    keyStorage.storeKey(kp);

    // Assert that rewriting of keys throws exception with valid messages.
    IOException ioException = assertThrows(IOException.class,
        () -> keyStorage.storeKey(kp));
    assertThat(ioException.getMessage())
        .contains("Private Key file already exists.");
    FileUtils.deleteQuietly(Paths.get(
        securityConfig.getKeyLocation(component).toString() + "/" + securityConfig
            .getPrivateKeyFileName()).toFile());
    ioException = assertThrows(IOException.class,
        () -> keyStorage.storeKey(kp));
    assertThat(ioException.getMessage())
        .contains("Public Key file already exists.");
    FileUtils.deleteQuietly(Paths.get(
        securityConfig.getKeyLocation(component).toString() + "/" + securityConfig
            .getPublicKeyFileName()).toFile());

    // Should succeed now as both public and private key are deleted.
    keyStorage.storeKey(kp);
    // Should succeed with overwrite flag as true.
    keyStorage.storeKey(kp, true);

  }

  /**
   * Assert key rewrite fails in non Posix file system.
   */
  @Test
  public void testWriteKeyInNonPosixFS()
      throws Exception {
    KeyPair kp = keyGenerator.generateKey();
    KeyStorage keyStorage = new KeyStorage(securityConfig, component);
    keyStorage.setIsPosixFileSystem(() -> false);

    // Assert key rewrite fails in non Posix file system.
    IOException ioException = assertThrows(IOException.class,
        () -> keyStorage.storeKey(kp));
    assertThat(ioException.getMessage())
        .contains("Unsupported File System.");
  }

  @Test
  public void testReadWritePublicKeyWithoutArgs()
      throws NoSuchProviderException, NoSuchAlgorithmException, IOException,
      InvalidKeySpecException {

    KeyPair kp = keyGenerator.generateKey();
    KeyStorage keyStorage = new KeyStorage(securityConfig, component);
    keyStorage.storeKey(kp);

    PublicKey pubKey = keyStorage.readPublicKey();
    assertNotNull(pubKey);
  }
}
