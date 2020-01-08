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
package org.apache.hadoop.ozone.common;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.hdds.protocol.proto.HddsProtos;
import org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType;
import org.apache.hadoop.util.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Properties;
import java.util.UUID;

/**
 * The internal representation of the Data directory underneath certain
 * services.
 *
 * The basic structure is the following:
 * / workingDir
 *   / service specific dir
 *     / current
 *       / ...
 *     / VERSION
 *
 * Where
 *   - the workingDir should be configurable for the service
 *   - the service specific directory is the lowercase name of the NodeType
 *     hardcoded and should not be changing.
 *   - current is fixed and hardcoded compile time to hold the current actual
 *     metadata belongs to the service
 *   - VERSION file is a property file, that holds actual information about the
 *     service and the cluster "runtime" in which the service supposed to work.
 *
 * A VERSION file consists of the following minimum set of properties:
 *   - clusterID: unique immutable cluster identification string, practically
 *        any arbitrary string consistent throughout the cluster services, but
 *        the suggested format is CID-[UUID string].
 *        See {@link Storage#newClusterID()}.
 *   - cTime: the creation time of the VERSION file as a unix timestamp with
 *        milliseconds included.
 *   - uTime: the last update time of the VERSION file.
 *   - nodeType: the {@link NodeType} of the service for which this file
 *        belongs to.
 *
 * Guarantees:
 *   - state of Storage is
 *     - NOT_INITIALIZED
 *       - if the working directory does not exists
 *       - if the working directory is not a directory
 *       - if the working directory is not writable
 *       - if the working directory is inaccessible according to the current
 *           SecurityManager
 *       - if the VERSION file in the service specific directory does not exists
 *     - INITIALIZED
 *       - if the VERSION file and the current directory exists and accessible
 *     - In an inconsistent state reported by an Exception at instantiation
 *         otherwise
 *   - updating the VERSION file is atomic
 *   - once set the clusterID and nodeType is not allowed to be updated
 *       programmatically
 *
 * Implementors of this class are not allowed to access the underlying
 * facilities used to store the properties, but are allowed to update existing
 * properties and add new properties.
 * The internal logic of loading and saving the properties in the version file
 * is also hidden from implementors, properties are persisted automatically on
 * setting them.

 */
@InterfaceAudience.Private
public abstract class Storage {
  private static final Logger LOG = LoggerFactory.getLogger(Storage.class);

  static final String E_NOT_EXIST = "does not exist";
  static final String E_NOT_DIRECTORY = "is not a directory";
  static final String E_NOT_WRITEABLE = "is not writeable";
  static final String E_NOT_ACCESSIBLE = "is not accessible";
  static final String E_NOT_INITIALIZED = "is not initialized";
  static final String E_CURRENT_NOT_EMPTY = "is a non empty folder "
      + "but it does not have a VERSION file";
  static final String E_ALREADY_INITIALIZED = "is already initialized";
  static final String E_DIRECTORY_CREATION = "could not be created";
  static final String E_VERSION_FILE_CREATION = "VERSION file could not be "
      + "written.";

  private static final String STORAGE_FILE_VERSION = "VERSION";
  // this one should be private as well, after DNs are using this class
  // also to manage local storage.
  public static final String STORAGE_DIR_CURRENT = "current";

  private final NodeType nodeType;
  private final File root;
  private final File storageDir;

  private StorageInfo storageInfo;

  /**
   * Generate new clusterID.
   *
   * clusterID is a persistent attribute of the cluster.
   * It is generated when the cluster is created and remains the same
   * during the life cycle of the cluster.  When a new SCM node is initialized,
   * if this is a new cluster, a new clusterID is generated and stored.
   * @return new clusterID
   */
  public static String newClusterID() {
    return "CID-" + UUID.randomUUID().toString();
  }

  /**
   * Creates the Version file if not present,
   * otherwise returns with IOException.
   * @throws IOException
   */
  protected static synchronized void initialize(
      NodeType nodeType, File workingDir, String clusterId, Properties props)
      throws IOException {
    ensureInitializationAllowed(nodeType, workingDir);
    ensureCurrentDirExists(nodeType, workingDir);


    StorageInfo info = new StorageInfo(nodeType, clusterId, Time.now());
    if (props!=null) {
      for (String key : props.stringPropertyNames()) {
        info.setProperty(key, props.getProperty(key));
      }
    }

    File versionFile = versionFileFor(workingDir, nodeType);
    try {
      info.writeTo(versionFile);
    } catch (IOException e) {
      warnAndThrow(E_VERSION_FILE_CREATION, versionFile, e);
    }
  }

  static File versionFileFor(File workingDir, NodeType type){
    return new File(currentDirFor(workingDir, type), STORAGE_FILE_VERSION);
  }

  static File currentDirFor(File workingDir, NodeType type){
    return new File (nodeDirFor(workingDir, type), STORAGE_DIR_CURRENT);
  }




  /**
   * Determines the state of the Version file.
   */
  public enum StorageState {
    INITIALIZED;

  }
  public Storage(NodeType type, File root)
      throws IOException {
    ensureDirIsInitializedFor(type, root);
    this.nodeType = type;
    this.root = root;
    this.storageDir = nodeDirFor(root, type);
    this.storageInfo = new StorageInfo(type, versionFileFor(root, type));
  }

  /**
   * Gets the path of the Storage dir.
   * @return Storage dir path
   */
  public String getStorageDir() {
    return storageDir.getAbsoluteFile().toString();
  }

  /**
   * Gets the state of the version file.
   * @return the state of the Version file
   */
  public StorageState getState() {
    return StorageState.INITIALIZED;
  }

  public NodeType getNodeType() {
    return storageInfo.getNodeType();
  }

  public String getClusterID() {
    return storageInfo.getClusterID();
  }

  /**
   * Directory {@code current} contains latest files defining
   * the file system meta-data.
   *
   * @return the directory path
   */
  public File getCurrentDir() {
    return currentDirFor(root, nodeType);
  }

  public long getCreationTime() {
    return storageInfo.getCreationTime();
  }

  //This method is used only from tests, and from OM and SCM initialization
  //Can we change this to a constructor parameter?
  public void setClusterId(String clusterId) throws IOException {
    throw new IOException(
        "Storage directory " + storageDir + " already initialized.");
  }
  protected void setProperty(String key, String value) {
    storageInfo.setProperty(key, value);
  }

  protected String getProperty(String key) {
    return storageInfo.getProperty(key);
  }

  abstract protected Properties getNodeProperties();

  /**
   * Sets the Node properties specific to OM/SCM.
   */
  private void setNodeProperties() {
    Properties nodeProperties = getNodeProperties();
    if (nodeProperties != null) {
      for (String key : nodeProperties.stringPropertyNames()) {
        storageInfo.setProperty(key, nodeProperties.getProperty(key));
      }
    }
  }

  /**
   * Persists current StorageInfo to file system..
   * @throws IOException
   */
  public void persistCurrentState() throws IOException {
    if (!currentDirFor(root, nodeType).exists()) {
      throw new IOException("Metadata dir doesn't exist, dir: " +
          getCurrentDir());
    }
    storageInfo.writeTo(versionFileFor(root, nodeType));
  }





  private void ensureDirIsInitializedFor(NodeType nodeType, File directory)
      throws IOException {
    assert directory != null : "root is null";
    try {
      if (!directory.exists()) {
        warnAndThrow(E_NOT_EXIST, directory, null);
      }
      if (!directory.isDirectory()) {
        warnAndThrow(E_NOT_DIRECTORY, directory, null);
      }
      if (!FileUtil.canWrite(directory)) {
        warnAndThrow(E_NOT_WRITEABLE, directory, null);
      }
    } catch (SecurityException ex) {
      warnAndThrow(E_NOT_ACCESSIBLE, directory, ex);
    }

    ensureDirectoryStructureFor(nodeType, directory);
  }

  private void ensureDirectoryStructureFor(NodeType nodeType, File directory)
      throws IOException {
    if (!versionFileFor(directory, nodeType).exists()){
      ensureCurrentFolderIsEmptyOrThrowInconsistentState(nodeType, directory);
      warnAndThrow(E_NOT_INITIALIZED, directory, null);
    }
  }

  private void ensureCurrentFolderIsEmptyOrThrowInconsistentState(
      NodeType nodeType, File workingDir) throws IOException {
    File currentDir = currentDirFor(workingDir, nodeType);
    if (!isEmptyOrNonExistingDirectory(currentDir)){
      String msg = "There is content in the current directory but the VERSION "
          + "file does not exist.";
      InconsistentStorageStateException ex =
          new InconsistentStorageStateException(msg);
      warnAndThrow(E_CURRENT_NOT_EMPTY, currentDir, ex);
    }
  }

  private static void warnAndThrow(String msg, File f, Throwable cause)
      throws IOException {
    String loggedMsg = "Storage directory: " + f.getCanonicalPath()
        + " " + msg + ".";
    LOG.warn(loggedMsg, cause);
    throw new IOException(loggedMsg, cause);
  }

  private static File nodeDirFor(File workingDir, NodeType type) {
    return new File(workingDir, type.name().toLowerCase());
  }

  private static void ensureInitializationAllowed(
      NodeType type, File workingDir) throws IOException {
    if (workingDir.exists() && !nodeTypeNotInitializedIn(workingDir, type)){
      String loggedMsg = "Storage directory: " + workingDir.getCanonicalPath()
          + " " + E_ALREADY_INITIALIZED + ".";
      LOG.info(loggedMsg);
      throw new StorageAlreadyInitializedException(loggedMsg);
    }
  }

  private static boolean nodeTypeNotInitializedIn(
      File workingDir, NodeType type) {
    File nodeDir = nodeDirFor(workingDir, type);
    File currentDir = currentDirFor(workingDir, type);
    return !nodeDir.exists() || isEmptyOrNonExistingDirectory(currentDir);
  }

  private static void ensureCurrentDirExists(NodeType nodeType, File workingDir)
      throws IOException {
    File currentDir = currentDirFor(workingDir, nodeType);
    if (!currentDir.mkdirs()) {
      warnAndThrow(E_DIRECTORY_CREATION, currentDir, null);
    }
  }

  private static boolean isEmptyOrNonExistingDirectory(File directory){
    return !directory.exists() ||
        directory.isDirectory() && directory.list().length == 0;
  }

}

