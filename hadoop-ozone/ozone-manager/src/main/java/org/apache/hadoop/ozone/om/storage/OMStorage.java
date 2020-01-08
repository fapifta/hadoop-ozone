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
package org.apache.hadoop.ozone.om.storage;

import java.io.File;
import java.io.IOException;
import java.util.Properties;
import java.util.UUID;

import org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType;
import org.apache.hadoop.ozone.common.Storage;

/**
 * OMStorage is responsible for management of the StorageDirectories used by
 * the Ozone Manager.
 */
public class OMStorage extends Storage {

  private static final String OM_ID = "omUuid";
  private static final String SCM_ID = "scmUuid";
  private static final String OM_CERT_SERIAL_ID = "omCertSerialId";

  public static synchronized void initialize(
      File workingDir, String clusterId, String scmId)
      throws IOException {
    Properties props = createOMSpecificProperties(scmId);
    Storage.initialize(NodeType.OM, workingDir, clusterId, props);
  }

  private static Properties createOMSpecificProperties(String scmId) {
    Properties props = new Properties();
    props.setProperty(OM_ID, UUID.randomUUID().toString());
    props.setProperty(SCM_ID, scmId);
    return props;
  }

  /**
   * Construct OMStorage.
   * @throws IOException if any directories are inaccessible.
   */
  public OMStorage(File workingDir) throws IOException {
    super(NodeType.OM, workingDir);
  }

  public void setOmCertSerialId(String certSerialId) throws IOException {
    setProperty(OM_CERT_SERIAL_ID, certSerialId);
  }

  /**
   * Retrieves the SCM ID from the version file.
   * @return SCM_ID
   */
  public String getScmId() {
    return getProperty(SCM_ID);
  }

  /**
   * Retrieves the OM ID from the version file.
   * @return OM_ID
   */
  public String getOmId() {
    return getProperty(OM_ID);
  }

  /**
   * Retrieves the serial id of certificate issued by SCM.
   * @return OM_ID
   */
  public String getOmCertSerialId() {
    return getProperty(OM_CERT_SERIAL_ID);
  }
}