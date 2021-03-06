/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hdds.utils.db;

import java.io.IOException;
import com.google.common.primitives.Shorts;

/**
 * Codec to convert Short to/from byte array.
 */
public class ShortCodec implements Codec<Short> {

  @Override
  public byte[] toPersistedFormat(Short object) throws IOException {
    return Shorts.toByteArray(object);
  }

  @Override
  public Short fromPersistedFormat(byte[] rawData) throws IOException {
    return Shorts.fromByteArray(rawData);
  }

  @Override
  public Short copyObject(Short object) {
    return object;
  }
}
