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

import java.security.cert.CertPath;
import java.util.function.Predicate;

/**
 * Certificate storage for reading in all certificates.
 */
public class AllCertStorage extends CertificateStorage {
  private static final Logger LOG =
      LoggerFactory.getLogger(AllCertStorage.class);

  public AllCertStorage(SecurityConfig securityConfig, String componentName) {
    super(securityConfig, componentName);
  }

  @Override
  public Logger getLogger() {
    return LOG;
  }

  /**
   * Returns true for all certificates.
   *
   * @return true for all certificates
   */
  @Override
  public Predicate<CertPath> getCertificateFilter() {
    return certPath -> true;
  }
}
