package org.apache.hadoop.ozone.common;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType;
import org.apache.hadoop.test.GenericTestUtils;
import org.apache.hadoop.util.Time;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

public class TestStorage {

  @Rule
  public ExpectedException ex = ExpectedException.none();

  private final NodeType testNodeType = NodeType.DATANODE;

  @Test
  public void testInstantiationFailsIfWorkDirDoesNotExists() throws Exception {
    ex.expect(IOException.class);
    ex.expectMessage(Storage.E_NOT_EXIST);

    aStorageImplWith(aNonExistingFile());
  }

  @Test
  public void testInstantiationFailsIfWorkDirIsNotADirectory() throws Exception {
    ex.expect(IOException.class);
    ex.expectMessage(Storage.E_NOT_DIRECTORY);

    aStorageImplWith(aFile());
  }

  @Test
  public void testInstantiationFailsIfWorkDirIsNotWriteable() throws Exception {
    ex.expect(IOException.class);
    ex.expectMessage(Storage.E_NOT_WRITEABLE);

    aStorageImplWith(aNonWritableDirectory());
  }

  @Test
  public void testInstantiationFailsIfWorkDirAccessThrowsSecurityException()
      throws Exception {
    ex.expect(IOException.class);
    ex.expectCause(IsInstanceOf.any(SecurityException.class));
    ex.expectMessage(Storage.E_NOT_ACCESSIBLE);

    aStorageImplWith(aNonAccessibleFile());
  }

  @Test
  public void testInstantiationFailsIfWorkDirIsNotInitialized()
      throws Exception {
    ex.expect(IOException.class);
    ex.expectMessage(Storage.E_NOT_INITIALIZED);

    aStorageImplWith(aWriteableDirectory());
  }

  @Test
  public void testInstantiationFailsIfNonEmptyCurrentDirWithVersionFileExists()
      throws Exception {
    ex.expect(IOException.class);
    ex.expectCause(IsInstanceOf.any(InconsistentStorageStateException.class));
    ex.expectMessage(Storage.E_CURRENT_NOT_EMPTY);

    File workingDir = aRealDirectory();
    File currentDir = Storage.currentDirFor(workingDir, testNodeType);
    currentDir.mkdirs();
    File f = new File(currentDir, aPath());
    f.createNewFile();

    aStorageImplWith(workingDir);
  }

  @Test
  public void testInstantiationFailsIfVersionFileDoesNotExist()
      throws Exception {
    ex.expect(IOException.class);
    ex.expectMessage(Storage.E_NOT_INITIALIZED);

    aStorageImplWith(aWriteableDirectory());
  }

  @Test
  public void
  testStorageDirIsTheCompositionOfWorkingDirAndServiceName()
      throws Exception {
    File workingDir = aRealDirectory();
    Storage storage = aStorageImplWithRealVersionFile(
        workingDir, propsForDNWithClusterIdAs1AndCTimeAs0()
    );

    String serviceTypeName = testNodeType.name().toLowerCase();
    String expectedDir =
        new File(workingDir, serviceTypeName).getAbsoluteFile().toString();
    assertEquals(expectedDir, storage.getStorageDir());
  }

  @Test
  public void testVersionFilePropertiesAreReadCorrectlyIfInitialized()
      throws Exception {
    Storage storage = aStorageImplWithRealVersionFile(
        aRealDirectory(), propsForDNWithClusterIdAs1AndCTimeAs0()
    );

    assertEquals(testNodeType, storage.getNodeType());
    assertEquals("1", storage.getClusterID());
  }

  @Test
  public void testVersionFilePropertiesAreSetIfInitializing() throws Exception {
    File workingDir = aRealDirectory();
    Storage.initialize(testNodeType, workingDir, Storage.newClusterID(), null);
    Storage storage = aStorageImplWith(workingDir);

    Properties props = loadPropertiesFromVersionFile(workingDir);

    assertEquals(props.getProperty("nodeType"), storage.getNodeType().name());
    assertEquals(props.getProperty("clusterID"), storage.getClusterID());
  }

  @Test
  public void testAdditionalPropertiesSavedIfInitializing() throws Exception {
    File workingDir = aRealDirectory();
    Properties extraProps =
        new Properties(propsForDNWithClusterIdAs1AndCTimeAs0());
    extraProps.setProperty("extraProp1", "value1");
    extraProps.setProperty("extraProp2", "value2");
    Storage.initialize(
        testNodeType, workingDir, Storage.newClusterID(), extraProps
    );

    Properties props = loadPropertiesFromVersionFile(workingDir);

    assertEquals(props.getProperty("extraProp1"), "value1");
    assertEquals(props.getProperty("extraProp2"), "value2");
  }

  @Test
  public void testPersistingCurrentStateSavesChanges()
      throws Exception{
    File workingDir = aRealDirectory();
    Storage storage = aStorageImplWithRealVersionFile(
        workingDir, propsForDNWithClusterIdAs1AndCTimeAs0()
    );
    long t = Time.monotonicNow();
    storage.setProperty("cTime", Long.toString(t));
    storage.setProperty("aPropertyKey", "aValue");
    storage.persistCurrentState();

    Properties props = loadPropertiesFromVersionFile(workingDir);

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
    props.setProperty("nodeType", testNodeType.name());
    props.setProperty("clusterID", "1");
    props.setProperty("cTime", "0");
    return props;
  }

  private Storage aStorageImplWith(File workingDir) throws Exception {
    return new Storage(testNodeType, workingDir){};
  }

  private Storage aStorageImplWithRealVersionFile(
      File workingDir, Properties props) throws Exception {
    File currentDir = Storage.currentDirFor(workingDir, testNodeType);
    currentDir.mkdirs();
    File versionFile = Storage.versionFileFor(workingDir, testNodeType);
    props.store(new FileWriter(versionFile), null);

    return aStorageImplWith(workingDir);
  }

  private Properties loadPropertiesFromVersionFile(File workingDir)
      throws Exception {
    File versionFile = Storage.versionFileFor(workingDir, testNodeType);
    Properties props = new Properties();
    props.load(new FileReader(versionFile));
    return props;
  }
}
