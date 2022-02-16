/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership.  The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.ozone.om.request.validation;

import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.apache.hadoop.ozone.om.request.validation.RequestProcessingPhase.POST_PROCESS;
import static org.apache.hadoop.ozone.om.request.validation.RequestProcessingPhase.PRE_PROCESS;
import static org.apache.hadoop.ozone.om.request.validation.ValidationCondition.CLUSTER_NEEDS_FINALIZATION;
import static org.apache.hadoop.ozone.om.request.validation.ValidationCondition.NEWER_CLIENT_REQUESTS;
import static org.apache.hadoop.ozone.om.request.validation.ValidationCondition.OLDER_CLIENT_REQUESTS;
import static org.apache.hadoop.ozone.om.request.validation.ValidationCondition.UNCONDITIONAL;
import static org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.Type.CreateKey;
import static org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.Type.CreateVolume;
import static org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.Type.DeleteKeys;

/**
 * Some annotated request validator method, and facilities to help check if
 * validations were properly called from tests where applicable.
 */
public final class GeneralValidatorsForTesting {

  private GeneralValidatorsForTesting() { }

  /**
   * Interface to easily add listeners that get notified if a certain validator
   * method defined in this class was called.
   *
   * @see TestRequestValidations for more details on how this intercace is
   *      being used.
   */
  @FunctionalInterface
  public interface ValidationListener {
    void validationCalled(String calledMethodName);
  }

  private static List<ValidationListener> listeners = new ArrayList<>();

  public static void addListener(ValidationListener listener) {
    listeners.add(listener);
  }

  public static void removeListener(ValidationListener listener) {
    listeners.remove(listener);
  }

  private static void fireValidationEvent(String calledMethodName) {
    listeners.forEach(l -> l.validationCalled(calledMethodName));
  }

  @RequestFeatureValidator(
      conditions = { CLUSTER_NEEDS_FINALIZATION },
      processingPhase = PRE_PROCESS,
      requestType = CreateKey)
  public static OMRequest preFinalizePreProcessCreateKeyValidator(
      OMRequest req, ValidationContext ctx) {
    fireValidationEvent("preFinalizePreProcessCreateKeyValidator");
    return req;
  }

  @RequestFeatureValidator(
      conditions = { CLUSTER_NEEDS_FINALIZATION },
      processingPhase = POST_PROCESS,
      requestType = CreateKey)
  public static OMResponse preFinalizePostProcessCreateKeyValidator(
      OMRequest req, OMResponse resp, ValidationContext ctx) {
    fireValidationEvent("preFinalizePostProcessCreateKeyValidator");
    return resp;
  }

  @RequestFeatureValidator(
      conditions = { NEWER_CLIENT_REQUESTS },
      processingPhase = PRE_PROCESS,
      requestType = CreateKey)
  public static OMRequest newClientPreProcessCreateKeyValidator(
      OMRequest req, ValidationContext ctx) {
    fireValidationEvent("newClientPreProcessCreateKeyValidator");
    return req;
  }

  @RequestFeatureValidator(
      conditions = { NEWER_CLIENT_REQUESTS },
      processingPhase = POST_PROCESS,
      requestType = CreateKey)
  public static OMResponse newClientPostProcessCreateKeyValidator(
      OMRequest req, OMResponse resp, ValidationContext ctx) {
    fireValidationEvent("newClientPostProcessCreateKeyValidator");
    return resp;
  }

  @RequestFeatureValidator(
      conditions = { OLDER_CLIENT_REQUESTS },
      processingPhase = PRE_PROCESS,
      requestType = CreateKey)
  public static OMRequest oldClientPreProcessCreateKeyValidator(
      OMRequest req, ValidationContext ctx) {
    fireValidationEvent("oldClientPreProcessCreateKeyValidator");
    return req;
  }

  @RequestFeatureValidator(
      conditions = { OLDER_CLIENT_REQUESTS },
      processingPhase = POST_PROCESS,
      requestType = CreateKey)
  public static OMResponse oldClientPostProcessCreateKeyValidator(
      OMRequest req, OMResponse resp, ValidationContext ctx) {
    fireValidationEvent("oldClientPostProcessCreateKeyValidator");
    return resp;
  }

  @RequestFeatureValidator(
      conditions = { UNCONDITIONAL },
      processingPhase = PRE_PROCESS,
      requestType = CreateKey)
  public static OMRequest unconditionalPreProcessCreateKeyValidator(
      OMRequest req, ValidationContext ctx) {
    fireValidationEvent("unconditionalPreProcessCreateKeyValidator");
    return req;
  }

  @RequestFeatureValidator(
      conditions = { UNCONDITIONAL },
      processingPhase = POST_PROCESS,
      requestType = CreateKey)
  public static OMResponse unconditionalPostProcessCreateKeyValidator(
      OMRequest req, OMResponse resp, ValidationContext ctx) {
    fireValidationEvent("unconditionalPostProcessCreateKeyValidator");
    return resp;
  }

  @RequestFeatureValidator(
      conditions = { CLUSTER_NEEDS_FINALIZATION, OLDER_CLIENT_REQUESTS },
      processingPhase = PRE_PROCESS,
      requestType = CreateVolume)
  public static OMRequest multiPurposePreProcessCreateVolumeValidator(
      OMRequest req, ValidationContext ctx) {
    fireValidationEvent("multiPurposePreProcessCreateVolumeValidator");
    return req;
  }

  @RequestFeatureValidator(
      conditions = { OLDER_CLIENT_REQUESTS, UNCONDITIONAL,
          CLUSTER_NEEDS_FINALIZATION },
      processingPhase = POST_PROCESS,
      requestType = CreateVolume)
  public static OMResponse multiPurposePostProcessCreateVolumeValidator(
      OMRequest req, OMResponse resp, ValidationContext ctx) {
    fireValidationEvent("multiPurposePostProcessCreateVolumeValidator");
    return resp;
  }

  @RequestFeatureValidator(
      conditions = { NEWER_CLIENT_REQUESTS },
      processingPhase = POST_PROCESS,
      requestType = CreateKey)
  public static OMResponse newClientPostProcessCreateKeyValidator2(
      OMRequest req, OMResponse resp, ValidationContext ctx) {
    fireValidationEvent("newClientPostProcessCreateKeyValidator2");
    return resp;
  }

  @RequestFeatureValidator(
      conditions = {UNCONDITIONAL},
      processingPhase = PRE_PROCESS,
      requestType = DeleteKeys
  )
  public static OMRequest throwingPreProcessValidator(
      OMRequest req, ValidationContext ctx) throws IOException {
    fireValidationEvent("throwingPreProcessValidator");
    throw new IOException("IOException: fail for testing...");
  }

  @RequestFeatureValidator(
      conditions = {UNCONDITIONAL},
      processingPhase = POST_PROCESS,
      requestType = DeleteKeys
  )
  public static OMResponse throwingPostProcessValidator(
      OMRequest req, OMResponse resp, ValidationContext ctx)
      throws IOException {
    fireValidationEvent("throwingPostProcessValidator");
    throw new IOException("IOException: fail for testing...");
  }
}
