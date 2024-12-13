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

import com.google.common.collect.Sets;
import org.apache.hadoop.hdds.security.SecurityConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.slf4j.Logger;

import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;

/**
 * Abstract base class for performing certificate related IO operations with the filesystem.
 */
public abstract class CertificateStorage {

  public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
  private static final String CERT_FILE_EXTENSION = ".crt";
  public static final String CERT_FILE_NAME_FORMAT = "%s" + CERT_FILE_EXTENSION;
  private final Set<PosixFilePermission> permissionSet = Sets.newHashSet(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE);

  private final SecurityConfig securityConfig;
  private final String componentName;

  protected CertificateStorage(SecurityConfig securityConfig, String componentName) {
    this.securityConfig = securityConfig;
    this.componentName = componentName;
  }

  public final List<OzoneCertPath> getCertPaths() {
    Path certificateLocation = getSecurityConfig().getCertificateLocation(getComponentName());
    if (!certificateLocation.toFile().exists()) {
      getLogger().error("CertificateLocation: {} doesn't exist", certificateLocation);
      return new ArrayList<>();
    }
    try (Stream<Path> certFiles = Files.list(certificateLocation)) {
      return certFiles
          .filter(Files::isRegularFile)
          .filter(getFileFilter())
          .map(this::readCertFile)
          .filter(Objects::nonNull)
          .filter(getCertificateFilter())
          .collect(Collectors.toList());
    } catch (IOException e) {
      getLogger().error("Error while reading certificates from path: {}", certificateLocation, e);
      return new ArrayList<>();
    }
  }

  public final KeyStore getKeyStore() throws IOException {
    try {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
      getCertPaths().forEach(certPath -> insertCertsToKeystore(keyStore, certPath));
      return keyStore;
    } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
      throw new IOException("Error while creating keystore", e);
    }
  }

  void insertCertsToKeystore(KeyStore keyStore, OzoneCertPath certPath) {
    X509Certificate cert = certPath.getLeafCert();
    try {
      keyStore.setCertificateEntry(cert.getSerialNumber().toString(), cert);
    } catch (KeyStoreException e) {
      getLogger().info("There was an error while creating the keystore.", e);
    }
  }

  abstract Predicate<OzoneCertPath> getCertificateFilter();

  public Predicate<Path> getFileFilter() {
    return path -> true;
  }

  public SecurityConfig getSecurityConfig() {
    return securityConfig;
  }

  public String getComponentName() {
    return componentName;
  }

  public abstract Logger getLogger();

  private OzoneCertPath readCertFile(Path filePath) {
    if (filePath == null) {
      getLogger().error("Trying to read null as a certificate file.");
      return null;
    }
    Path fileName = filePath.getFileName();
    if (fileName == null) {
      getLogger().error("Error the fileName is null for {}", filePath);
      return null;
    }
    try {
      return getCertPath(getSecurityConfig().getCertificateLocation(componentName), fileName.toString());
    } catch (IOException | CertificateException e) {
      getLogger().error("Error reading certificate from file: {}.", filePath, e);
      return null;
    }
  }

  public Set<X509Certificate> getLeafCertificates() {
    if (getCertPaths().isEmpty()) {
      getLogger().info("Leaf certificates are empty");
      return new HashSet<>();
    }
    return getCertPaths().stream()
        .map(OzoneCertPath::getLeafCert)
        .collect(Collectors.toSet());
  }

  public void storeCertificate(X509Certificate certificate) throws IOException {
    writeCertificate(securityConfig.getCertificateLocation(componentName), securityConfig.getCertificateFileName(),
        CertificateCodec.get().encode(certificate));
  }

  public String storeCertificate(String pemEncodedCert, CAType caType) throws IOException {
    return storeCertificate(pemEncodedCert, caType, securityConfig.getCertificateLocation(getComponentName()));
  }

  public void storeDefaultCertificate(String pemEncodedCert) throws IOException {
    writeCertificate(getSecurityConfig().getCertificateLocation(getComponentName()),
        getSecurityConfig().getCertificateFileName(), pemEncodedCert);
  }

  public void storeDefaultCertificate(X509Certificate certificate) throws IOException {
    storeDefaultCertificate(CertificateCodec.get().encode(certificate));
  }

  public String storeCertificate(String pemEncodedCert, CAType caType, Path path) throws IOException {
    OzoneCertPath certPath = CertificateCodec.get().decode(pemEncodedCert);
    String certId = certPath.getLeafCert().getSerialNumber().toString();
    String certName = String.format(CERT_FILE_NAME_FORMAT, caType.getFileNamePrefix() + certId);
    writeCertificate(path, certName, pemEncodedCert);
    return certId;
  }

  /**
   * Helper function that writes data to the file.
   *
   * @param basePath              - Base Path where the file needs to written
   *                              to.
   * @param fileName              - Certificate file name.
   * @param pemEncodedCertificate - pemEncoded Certificate file.
   * @throws IOException - on Error.
   */
  //This is only protected for special use in RotationHandlerStorage, please use various storeCertificate methods
  // instead
  protected synchronized void writeCertificate(Path basePath, String fileName,
      String pemEncodedCertificate)
      throws IOException {
    checkBasePathDirectory(basePath);
    File certificateFile =
        Paths.get(basePath.toString(), fileName).toFile();

    try (FileOutputStream file = new FileOutputStream(certificateFile)) {
      file.write(pemEncodedCertificate.getBytes(DEFAULT_CHARSET));
    }
    getLogger().info("Save certificate to {}", certificateFile.getAbsolutePath());
    getLogger().info("Certificate {}", pemEncodedCertificate);
    Files.setPosixFilePermissions(certificateFile.toPath(), permissionSet);
  }

  protected OzoneCertPath getCertPath(Path path, String fileName) throws IOException,
      CertificateException {
    checkBasePathDirectory(path.toAbsolutePath());
    File certFile =
        Paths.get(path.toAbsolutePath().toString(), fileName).toFile();
    if (!certFile.exists()) {
      throw new IOException("Unable to find the requested certificate file. " +
          "Path: " + certFile);
    }
    try (FileInputStream is = new FileInputStream(certFile)) {
      return CertificateCodec.get().decode(is);
    }
  }

  private void checkBasePathDirectory(Path basePath) throws IOException {
    if (!basePath.toFile().exists()) {
      if (!basePath.toFile().mkdirs()) {
        getLogger().error("Unable to create file path. Path: {}", basePath);
        throw new IOException("Creation of the directories failed."
            + basePath);
      }
    }
  }

}
