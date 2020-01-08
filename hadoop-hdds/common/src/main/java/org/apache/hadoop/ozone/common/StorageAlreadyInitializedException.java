package org.apache.hadoop.ozone.common;

import java.io.IOException;

/**
 * IOException specialization to indicate at Storage initialization time if a
 * storage directory has already been initialized and hence initialization is
 * not possible again.
 */
public class StorageAlreadyInitializedException extends IOException {
  public StorageAlreadyInitializedException(String msg) {
    super(msg);
  }
}
