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

import org.apache.hadoop.hdds.security.SecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.util.function.Predicate;

/**
 * Certificate storage implementation for reading and writing certificates configured as default in SecurityConfig.
 */
public class ConfiguredCertStorage extends CertificateStorage {

  private static final Logger LOG = LoggerFactory.getLogger(RotationHandlerStorage.class);

  public ConfiguredCertStorage(SecurityConfig securityConfig, String componentName) {
    super(securityConfig, componentName);
  }

  @Override
  public Predicate<Path> getFileFilter() {
    return path -> path.getFileName().toString().equals(getSecurityConfig().getCertificateFileName());
  }

  @Override
  Predicate<CertPath> getCertificateFilter() {
    return certPath -> true;
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  public void storeDefaultCertificate(String pemEncodedCert) throws IOException {
    writeCertificate(getSecurityConfig().getCertificateLocation(getComponentName()),
        getSecurityConfig().getCertificateFileName(), pemEncodedCert);
  }


}
