package org.apache.hadoop.ozone.common;

import static org.junit.Assert.*;

import org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeType;
import org.apache.hadoop.test.GenericTestUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Properties;

public class TestStorage {

  private File workDir;
  private Properties props;
  private Storage storage;

  @Before
  public void setupDummyInstance() throws IOException {
    workDir = GenericTestUtils.getRandomizedTestDir();
    workDir.deleteOnExit();
    storage = new Storage(NodeType.DATANODE, workDir, "test") {
      @Override protected Properties getNodeProperties() {
        return props;
      }
    };
  }

  @Test
  public void testStorageInNonExistentStateIfStorageDirectoryIsNotCreated(){
    assertTrue(Storage.StorageState.NON_EXISTENT.equals(storage.getState()));
  }


}
