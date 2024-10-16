/*
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

import org.apache.commons.io.FileUtils;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.apache.hadoop.hdds.security.x509.keys.KeyCodec;
import org.apache.hadoop.ozone.OzoneConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.util.function.Consumer;
import java.util.function.Predicate;

import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_NEW_KEY_CERT_DIR_NAME_PROGRESS_SUFFIX;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_X509_DIR_NAME_DEFAULT;

/**
 * Certificate storage implementation for helping certificate rotation.
 */
public class RotationHandlerStorage extends CertificateStorage {

  private static final Logger LOG = LoggerFactory.getLogger(RotationHandlerStorage.class);

  private File newProgressDir;
  private File newDir;
  private String progressComponent;
  private Consumer<String> scmShutdownHook;

  public RotationHandlerStorage(SecurityConfig securityConfig, String componentName,
      Consumer<String> scmShutdownHook) {
    super(securityConfig, componentName);
    this.scmShutdownHook = scmShutdownHook;
  }

  @Override
  Predicate<CertPath> getCertificateFilter() {
    return certPath -> true;
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  public void initNextDirs() {
    Path rotationComponentPath = Paths.get(OzoneConsts.SCM_CA_CERT_STORAGE_DIR,
        OzoneConsts.SCM_SUB_CA_PATH);
    progressComponent = rotationComponentPath +
        HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX +
        HDDS_NEW_KEY_CERT_DIR_NAME_PROGRESS_SUFFIX;
    final String newSubCAProgressPath =
        getSecurityConfig().getLocation(progressComponent).toString();
    final String newSubCAPath = getSecurityConfig().getLocation(rotationComponentPath +
        HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX).toString();

    newProgressDir = new File(newSubCAProgressPath);
    newDir = new File(newSubCAPath);
    try {
      FileUtils.deleteDirectory(newProgressDir);
      FileUtils.deleteDirectory(newDir);
      Files.createDirectories(newProgressDir.toPath());
    } catch (IOException e) {
      getLogger().error("Failed to delete and create {}, or delete {}",
          newProgressDir, newDir, e);
      String message = "Terminate SCM, encounter IO exception(" +
          e.getMessage() + ") when deleting and create directory";
      scmShutdownHook.accept(message);
    }
  }

  public KeyPair generateNewKeys(String rootCACertId) throws IOException {
    Path keyDir = getSecurityConfig().getKeyLocation(progressComponent);
    KeyCodec keyCodec = new KeyCodec(getSecurityConfig(), keyDir);
    KeyPair newKeyPair = null;
    try {
      HDDSKeyGenerator keyGenerator =
          new HDDSKeyGenerator(getSecurityConfig());
      newKeyPair = keyGenerator.generateKey();
      keyCodec.writePublicKey(newKeyPair.getPublic());
      keyCodec.writePrivateKey(newKeyPair.getPrivate());
      getLogger().info("SubCARotationPrepareTask[rootCertId = {}] - " +
          "scm key generated.", rootCACertId);
    } catch (Exception e) {
      getLogger().error("Failed to generate key under {}", newProgressDir, e);
      String message = "Terminate SCM, encounter exception(" +
          e.getMessage() + ") when generating new key under " +
          newProgressDir;
      scmShutdownHook.accept(message);
    }
    return newKeyPair;
  }

  public void storeNewCerts(CertPath newCert, CertPath newRootCaCert) throws IOException {
    Path newSubCaProgressPathX509 = Paths.get(newProgressDir.toString(), HDDS_X509_DIR_NAME_DEFAULT);
    storeCertificate(newCert, CAType.NONE, newSubCaProgressPathX509);
    storeCertificate(newRootCaCert, CAType.SUBORDINATE, newSubCaProgressPathX509);
    CertificateCodec certCodec = new CertificateCodec(getSecurityConfig(), newSubCaProgressPathX509);
    certCodec.writeCertificate(certCodec.getLocation().toAbsolutePath(),
        getSecurityConfig().getCertificateFileName(), CertificateCodec.getPEMEncodedString(newCert));
  }

  public void moveFromProgressToNext() {
    try {
      Files.move(newProgressDir.toPath(), newDir.toPath(),
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      LOG.error("Failed to move {} to {}",
          newProgressDir.toString(), newDir.toString(), e);
      String message = "Terminate SCM, encounter exception(" +
          e.getMessage() + ") when moving " + newProgressDir.toString() +
          " to " + newDir.toString();
      scmShutdownHook.accept(message);
    }
  }
}
