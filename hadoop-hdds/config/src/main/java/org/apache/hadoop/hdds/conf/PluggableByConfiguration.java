/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.hadoop.hdds.conf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation to denote classes that are to be injected to the system via a configuration option.
 *
 * The initial intention of this interface is to denote these classes, and make it easier for developers to understand
 * the usage of the class.
 * The target of this annotation should be the actual implementation class that can be plugged in via configuration
 * instead of the interface, and with that it should be used internally.
 *
 * As there are no further uses of the annotation as of now, initially retention is set to source, but as soon
 * as we see useful funtions with this at runtime, we can change it.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.SOURCE)
@Repeatable(PluggableByConfigurations.class)
public @interface PluggableByConfiguration {

  /**
   * The configuration property used to plug the class in.
   * @return the related configuration property.
   */
  String[] value();

  /**
   * Denotes if the annotated class is the default value.
   */
  boolean isDefault() default false;
}

