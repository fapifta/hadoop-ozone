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

import org.apache.hadoop.hdds.security.x509.certificate.authority.profile.PKIProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * CertificateServer that uses subordinate certificates signed by the RootCAServer.
 */
public class SubCAServer extends DefaultCAServer {
  public static final Logger LOG =
      LoggerFactory.getLogger(SubCAServer.class);

  public SubCAServer(String subject, String clusterID, String scmID, CertificateStore certificateStore,
      PKIProfile pkiProfile, String componentName) {
    super(subject, clusterID, scmID, certificateStore, pkiProfile, componentName);
  }

  @Override
  void initKeysAndRootCa() {

  }
}
