package org.apache.hadoop.ozone.common;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType;
import org.apache.hadoop.ozone.common.Storage.StorageState;
import org.apache.hadoop.test.GenericTestUtils;
import org.apache.hadoop.util.Time;
import org.junit.Test;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

public class TestStorage {

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotCreated()
      throws Exception {
    Storage storage = aStorageImplWith(aNonExistingFile());

    assertEquals(StorageState.NOT_INITIALIZED, storage.getState());
  }

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotADirectory()
      throws Exception {
    Storage storage = aStorageImplWith(aFile());

    assertEquals(StorageState.NOT_INITIALIZED, storage.getState());
  }

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotWritable()
      throws Exception {
    Storage storage = aStorageImplWith(aNonWritableDirectory());

    assertEquals(StorageState.NOT_INITIALIZED, storage.getState());
  }

  @Test
  public void
  testStorageInNonExistentStateIfStorageDirectoryAccessThrowsSecurityException()
      throws Exception {
    Storage storage = aStorageImplWith(aNonAccessibleFile());

    assertEquals(StorageState.NOT_INITIALIZED, storage.getState());
  }

  @Test
  public void testStorageInInitializedStateIfVersionFileExists()
      throws Exception {
    Storage storage = aStorageImplWithRealVersionFile(
        aRealDirectory(), propsForDNWithClusterIdAs1AndCTimeAs0()
    );

    assertEquals(StorageState.INITIALIZED, storage.getState());
  }

  @Test
  public void testStorageInNotInitializedStateIfVersionFileDoesNotExist()
      throws Exception {
    Storage storage = aStorageImplWith(aWriteableDirectory());

    assertEquals(StorageState.NOT_INITIALIZED, storage.getState());
  }

  @Test
  public void
  testStorageDirIsTheCompositionOfWorkingDirAndServiceName()
      throws Exception {
    File workingDir = aWriteableDirectory();

    Storage storage = new Storage(NodeType.DATANODE, workingDir) {
      @Override protected Properties getNodeProperties() {
        return null;
      }
    };

    String serviceTypeName = NodeType.DATANODE.name().toLowerCase();
    String expectedDir =
        new File(workingDir, serviceTypeName).getAbsoluteFile().toString();
    assertEquals(expectedDir, storage.getStorageDir());
  }

  @Test(expected = InconsistentStorageStateException.class)
  public void testNonEmptyCurrentWithoutVersionFilesLeadsToExceptionAtCTor()
      throws Exception {
    File workingDir = aRealDirectory();
    String serviceName = NodeType.DATANODE.name().toLowerCase();
    File storageDir = new File(workingDir, serviceName);
    File currentDir = new File(storageDir, Storage.STORAGE_DIR_CURRENT);
    currentDir.mkdirs();
    File f = new File(currentDir, aPath());
    f.createNewFile();

    aStorageImplWith(workingDir);
  }

  @Test
  public void testVersionFilePropertiesAreReadCorrectlyIfInitialized()
      throws Exception {
    Storage storage = aStorageImplWithRealVersionFile(
        aRealDirectory(), propsForDNWithClusterIdAs1AndCTimeAs0()
    );

    assertEquals(NodeType.DATANODE, storage.getNodeType());
    assertEquals("1", storage.getClusterID());
    assertEquals(0, storage.getCreationTime());
  }

  @Test
  public void testVersionFilePropertiesAreSetIfInitializing() throws Exception {
    File workingDir = aRealDirectory();
    Storage storage = aStorageImplWith(workingDir);
    storage.initialize();

    Properties props = loadPropertiesFromVersionFile(workingDir);

    assertEquals(props.getProperty("nodeType"), storage.getNodeType().name());
    assertEquals(props.getProperty("clusterID"), storage.getClusterID());
    assertEquals(
        props.getProperty("cTime"), Long.toString(storage.getCreationTime()));
  }

  @Test
  public void testAdditionalPropertiesSavedIfInitializing() throws Exception {
    File workingDir = aRealDirectory();
    Properties extraProps =
        new Properties(propsForDNWithClusterIdAs1AndCTimeAs0());
    extraProps.setProperty("extraProp1", "value1");
    extraProps.setProperty("extraProp2", "value2");
    Storage storage = aStorageImplWith(workingDir, extraProps);
    storage.initialize();

    Properties props = loadPropertiesFromVersionFile(workingDir);

    assertEquals(props.getProperty("extraProp1"), "value1");
    assertEquals(props.getProperty("extraProp2"), "value2");
  }

  @Test(expected = IOException.class)
  public void testUpdatesAreDisabledToClusterIDAfterInitialization()
      throws Exception {
    Storage storage = aStorageImplWith(
        aRealDirectory(), propsForDNWithClusterIdAs1AndCTimeAs0());
    storage.initialize();

    storage.setClusterId("newId");
  }

  @Test(expected = IOException.class)
  public void testUpdatesAreDisabledToClusterIDIfInitialized()
      throws Exception {
    Storage storage = aStorageImplWithRealVersionFile(
        aRealDirectory(), propsForDNWithClusterIdAs1AndCTimeAs0()
    );

    storage.setClusterId("newId");
  }

  @Test
  public void testPersistingCurrentStateSavesChanges()
      throws Exception{
    File workingDir = aRealDirectory();
    Storage storage = aStorageImplWith(workingDir);
    storage.initialize();
    long t = Time.monotonicNow();
    storage.setProperty("cTime", Long.toString(t));
    storage.setProperty("aPropertyKey", "aValue");
    storage.persistCurrentState();

    Properties props = loadPropertiesFromVersionFile(workingDir);

    assertEquals(t, storage.getCreationTime());
    assertEquals(t, Long.parseLong(props.getProperty("cTime")));
    assertEquals("aValue", props.getProperty("aPropertyKey"));
  }




  private String aPath(){
    return "aPath";
  }

  private File aNonExistingFile() {
    return spy(new File(aPath()));
  }

  private File aFile(){
    File f = spy(new File(aPath()));
    doReturn(true).when(f).exists();
    doReturn(false).when(f).isDirectory();
    doReturn(true).when(f).isFile();
    return f;
  }

  private File aRealDirectory(){
    File f = GenericTestUtils.getRandomizedTestDir();
    f.mkdirs();
    f.deleteOnExit();
    return f;
  }

  private File aWriteableDirectory(){
    File f = spy(new File(aPath()));
    doReturn(true).when(f).exists();
    doReturn(true).when(f).isDirectory();
    doReturn(false).when(f).isFile();
    doReturn(true).when(f).canWrite();
    return f;
  }

  private File aNonWritableDirectory() {
    File f = spy(new File(aPath()));
    doReturn(true).when(f).exists();
    doReturn(true).when(f).isDirectory();
    doReturn(false).when(f).canWrite();
    return f;
  }

  private File aNonAccessibleFile(){
    File f = spy(new File(aPath()));
    doThrow(new SecurityException()).when(f).exists();
    return f;
  }

  private Properties propsForDNWithClusterIdAs1AndCTimeAs0(){
    Properties props = new Properties();
    props.setProperty("nodeType", NodeType.DATANODE.name());
    props.setProperty("clusterID", "1");
    props.setProperty("cTime", "0");
    return props;
  }

  private Storage aStorageImplWith(File workingDir) throws Exception {
    return aStorageImplWith(workingDir, null);
  }

  private Storage aStorageImplWith(File workingDir, Properties props)
      throws IOException {
    return new Storage(NodeType.DATANODE, workingDir) {
      @Override
      protected Properties getNodeProperties() {
        return props;
      }
    };
  }

  private Storage aStorageImplWithRealVersionFile(
      File workingDir, Properties props) throws Exception {
    String serviceName = NodeType.DATANODE.name().toLowerCase();
    String currentDirPath = serviceName + "/" + Storage.STORAGE_DIR_CURRENT;
    File actualDir = new File (workingDir, currentDirPath);
    actualDir.mkdirs();
    File versionFile = new File(actualDir, Storage.STORAGE_FILE_VERSION);
    props.store(new FileWriter(versionFile), null);

    return aStorageImplWith(workingDir, props);
  }

  private Properties loadPropertiesFromVersionFile(File workingDir)
      throws Exception {
    String serviceName = NodeType.DATANODE.name().toLowerCase();
    String currentDirPath = serviceName + "/" + Storage.STORAGE_DIR_CURRENT;
    File storageDir = new File (workingDir, currentDirPath);
    File versionFile = new File(storageDir, Storage.STORAGE_FILE_VERSION);
    Properties props = new Properties();
    props.load(new FileReader(versionFile));
    return props;
  }
}
