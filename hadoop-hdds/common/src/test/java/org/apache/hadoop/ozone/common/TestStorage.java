package org.apache.hadoop.ozone.common;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType;
import org.apache.hadoop.ozone.common.Storage.StorageState;
import org.junit.Test;

import java.io.File;
import java.util.Properties;

public class TestStorage {

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotCreated()
      throws Exception {
    Storage storage = aStorageImplWith(aNonExistingFile());

    assertTrue(StorageState.NON_EXISTENT.equals(storage.getState()));
  }

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotADirectory()
      throws Exception {
    Storage storage = aStorageImplWith(aFile());

    assertTrue(StorageState.NON_EXISTENT.equals(storage.getState()));
  }

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotWritable()
      throws Exception {
    Storage storage = aStorageImplWith(aNonWritableDirectory());

    assertTrue(StorageState.NON_EXISTENT.equals(storage.getState()));
  }

  @Test
  public void
  testStorageInNonExistentStateIfStorageDirectoryAccessThrowsSecurityException()
      throws Exception {
    Storage storage = aStorageImplWith(aNonAccessibleFile());

    assertTrue(StorageState.NON_EXISTENT.equals(storage.getState()));
  }



  private File aNonExistingFile() {
    return spy(new File("aPath"));
  }

  private File aFile(){
    File f = spy(new File("aPath"));
    doReturn(true).when(f).exists();
    doReturn(false).when(f).isDirectory();
    doReturn(true).when(f).isFile();
    return f;
  }

  private File aNonWritableDirectory() {
    File f = spy(new File("aPath"));
    doReturn(true).when(f).exists();
    doReturn(true).when(f).isDirectory();
    doReturn(false).when(f).canWrite();
    return f;
  }

  private File aNonAccessibleFile(){
    File f = spy(new File("aPath"));
    doThrow(new SecurityException()).when(f).exists();
    return f;
  }

  private Storage aStorageImplWith(File workingDir) throws Exception {
    return aStorageImplWith(workingDir, null);
  }

  private Storage aStorageImplWith(File workingDir, Properties props)
      throws Exception {
    return new Storage(NodeType.DATANODE, workingDir, "test") {
      @Override protected Properties getNodeProperties() {
        return props;
      }
    };
  }
}
