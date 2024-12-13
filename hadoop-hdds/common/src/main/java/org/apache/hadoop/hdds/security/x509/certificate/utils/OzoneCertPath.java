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

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Wrapper class for CertPath to avoid repeatedly calling the body of getLeafCert.
 */
public class OzoneCertPath {

  private final CertPath certPath;

  public OzoneCertPath(CertPath certificatePath) {
    this.certPath = certificatePath;
  }

  public List<? extends Certificate> getCertificates() {
    return certPath.getCertificates();
  }

  public X509Certificate getLeafCert() {
    if (certPath != null) {
      return (X509Certificate) certPath.getCertificates().get(0);
    }
    return null;
  }
}
