package org.apache.hadoop.ozone.common;

import java.io.IOException;

public class StorageAlreadyInitializedException extends IOException {
  public StorageAlreadyInitializedException(String msg) {
    super(msg);
  }

  public StorageAlreadyInitializedException(String msg, Throwable cause) {
    super(msg, cause);
  }
}
