/**
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
package org.apache.hadoop.ozone.protocolPB;

import static org.apache.hadoop.ozone.om.ratis.OzoneManagerRatisServer.RaftServerStatus.LEADER_AND_READY;
import static org.apache.hadoop.ozone.om.ratis.OzoneManagerRatisServer.RaftServerStatus.NOT_LEADER;
import static org.apache.hadoop.ozone.om.ratis.utils.OzoneManagerRatisUtils.createClientRequest;
import static org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.Type.PrepareStatus;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.hadoop.hdds.server.OzoneProtocolMessageDispatcher;
import org.apache.hadoop.hdds.tracing.TracingUtil;
import org.apache.hadoop.hdds.utils.ProtocolMessageMetrics;
import org.apache.hadoop.ozone.OmUtils;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.exceptions.OMLeaderNotReadyException;
import org.apache.hadoop.ozone.om.exceptions.OMNotLeaderException;
import org.apache.hadoop.ozone.om.protocolPB.OzoneManagerProtocolPB;
import org.apache.hadoop.ozone.om.ratis.OzoneManagerDoubleBuffer;
import org.apache.hadoop.ozone.om.ratis.OzoneManagerRatisServer;
import org.apache.hadoop.ozone.om.ratis.OzoneManagerRatisServer.RaftServerStatus;
import org.apache.hadoop.ozone.om.ratis.utils.OzoneManagerRatisUtils;
import org.apache.hadoop.ozone.om.request.OMClientRequest;
import org.apache.hadoop.ozone.om.request.validation.RequestFeatureValidator;
import org.apache.hadoop.ozone.om.request.validation.RequestProcessingPhase;
import org.apache.hadoop.ozone.om.request.validation.ValidationCondition;
import org.apache.hadoop.ozone.om.request.validation.ValidationContext;
import org.apache.hadoop.ozone.om.request.validation.ValidatorRegistry;
import org.apache.hadoop.ozone.om.response.OMClientResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMResponse;

import com.google.protobuf.ProtocolMessageEnum;
import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;
import org.apache.hadoop.ozone.security.S3SecurityUtil;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.util.ExitUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is the server-side translator that forwards requests received on
 * {@link OzoneManagerProtocolPB}
 * to the OzoneManagerService server implementation.
 */
public class OzoneManagerProtocolServerSideTranslatorPB implements
    OzoneManagerProtocolPB {
  private static final Logger LOG = LoggerFactory
      .getLogger(OzoneManagerProtocolServerSideTranslatorPB.class);
  private static final String OM_REQUESTS_PACKAGE = 
      "org.apache.hadoop.ozone";
  
  private final OzoneManagerRatisServer omRatisServer;
  private final RequestHandler handler;
  private final boolean isRatisEnabled;
  private final OzoneManager ozoneManager;
  private final OzoneManagerDoubleBuffer ozoneManagerDoubleBuffer;
  private final AtomicLong transactionIndex;
  private final OzoneProtocolMessageDispatcher<OMRequest, OMResponse,
      ProtocolMessageEnum> dispatcher;
  private final ValidatorRegistry validatorRegistry;

  /**
   * Constructs an instance of the server handler.
   *
   * @param impl OzoneManagerProtocolPB
   */
  public OzoneManagerProtocolServerSideTranslatorPB(
      OzoneManager impl,
      OzoneManagerRatisServer ratisServer,
      ProtocolMessageMetrics<ProtocolMessageEnum> metrics,
      boolean enableRatis,
      long lastTransactionIndexForNonRatis) {
    this.ozoneManager = impl;
    this.isRatisEnabled = enableRatis;
    // Update the transactionIndex with the last TransactionIndex read from DB.
    // New requests should have transactionIndex incremented from this index
    // onwards to ensure unique objectIDs.
    this.transactionIndex = new AtomicLong(lastTransactionIndexForNonRatis);

    if (isRatisEnabled) {
      // In case of ratis is enabled, handler in ServerSideTransaltorPB is used
      // only for read requests and read requests does not require
      // double-buffer to be initialized.
      this.ozoneManagerDoubleBuffer = null;
      handler = new OzoneManagerRequestHandler(impl, null);
    } else {
      this.ozoneManagerDoubleBuffer = new OzoneManagerDoubleBuffer.Builder()
          .setOmMetadataManager(ozoneManager.getMetadataManager())
          // Do nothing.
          // For OM NON-HA code, there is no need to save transaction index.
          // As we wait until the double buffer flushes DB to disk.
          .setOzoneManagerRatisSnapShot((i) -> {
          })
          .enableRatis(isRatisEnabled)
          .enableTracing(TracingUtil.isTracingEnabled(
              ozoneManager.getConfiguration()))
          .build();
      handler = new OzoneManagerRequestHandler(impl, ozoneManagerDoubleBuffer);
    }
    this.omRatisServer = ratisServer;
    dispatcher = new OzoneProtocolMessageDispatcher<>("OzoneProtocol",
        metrics, LOG, OMPBHelper::processForDebug, OMPBHelper::processForDebug);
    // TODO: make this injectable for testing...
    validatorRegistry = new ValidatorRegistry(OM_REQUESTS_PACKAGE);
  }

  /**
   * Submit requests to Ratis server for OM HA implementation.
   * TODO: Once HA is implemented fully, we should have only one server side
   * translator for OM protocol.
   */
  @Override
  public OMResponse submitRequest(RpcController controller,
      OMRequest request) throws ServiceException {
    List<ValidationCondition> conditions = getConditions(request);
    ValidationContext context = ValidationContext.of(
        ozoneManager.getVersionManager(), 0, request.getVersion());

    OMRequest validatedRequest = preValidate(conditions, context, request);

    OMResponse response = 
        dispatcher.processRequest(validatedRequest, this::processRequest,
        request.getCmdType(), request.getTraceID());
    
    return postValidate(conditions, context, validatedRequest, response);
  }

  //TODO: move this code out from here, and just call from a validation util
  //      class or instead of gettign the validation from the registry we
  //      might even use that to run the validations...
  private OMRequest preValidate(
      List<ValidationCondition> conditions,
      ValidationContext context,
      OMRequest originalRequest) throws ServiceException {

    List<Method> validations = validatorRegistry.validationsFor(
        conditions,
        originalRequest.getCmdType(),
        RequestProcessingPhase.PRE_PROCESS);


    OMRequest validatedRequest = originalRequest.toBuilder().build();
    for (Method method : validations) {
      // TODO: restrict the parameter list and return type of such annotated
      //       methods either at compile time, or via a test
      try {
        if (method
            .getAnnotation(RequestFeatureValidator.class).contextAware()) {
          validatedRequest =
              (OMRequest) method.invoke(null, validatedRequest, context);
        } else {
          validatedRequest =
              (OMRequest) method.invoke(null, validatedRequest);
        }
      } catch (IllegalAccessException | InvocationTargetException e) {
        throw new ServiceException(e);
      }
    }
    return validatedRequest;
  }

  private OMResponse postValidate(
      List<ValidationCondition> conditions,
      ValidationContext context,
      OMRequest originalRequest,
      OMResponse originalResponse) throws ServiceException {

    List<Method> validations = validatorRegistry.validationsFor(
        conditions,
        originalRequest.getCmdType(),
        RequestProcessingPhase.POST_PROCESS);

    OMResponse validatedResponse = originalResponse.toBuilder().build();
    for (Method method : validations) {
      // TODO: restrict the parameter list and return type of such annotated
      //       methods either at compile time, or via a test
      try {
        if (method.getAnnotation(RequestFeatureValidator.class).contextAware()) {
          validatedResponse = (OMResponse) method
              .invoke(null, originalRequest, validatedResponse, context);
        } else {
          validatedResponse = (OMResponse) method
              .invoke(null, originalRequest, validatedResponse);
        }
      } catch (IllegalAccessException | InvocationTargetException e) {
        throw new ServiceException(e);
      }
    }
    return validatedResponse;
  }

  private List<ValidationCondition> getConditions(OMRequest request) {
    List<ValidationCondition> conditions = new LinkedList<>();
    conditions.add(ValidationCondition.UNCONDITIONAL);
    int serverProtocolVersion = getServerProtocolVersion();
    int clientProtocolVersion = request.getVersion();
    if (serverProtocolVersion < clientProtocolVersion) {
      conditions.add(ValidationCondition.NEWER_CLIENT_REQUESTS);
    } else if (serverProtocolVersion > clientProtocolVersion) {
      conditions.add(ValidationCondition.OLDER_CLIENT_REQUESTS);
    }
    if (ozoneManager.getVersionManager().needsFinalization()) {
      conditions.add(ValidationCondition.CLUSTER_IS_PRE_FINALIZED);
    }
    return conditions;
  }

  //TODO fidn out versioning and where it comes from...
  private int getServerProtocolVersion() {
    return 0;
  }

  private OMResponse processRequest(OMRequest request) throws
      ServiceException {
    if (isRatisEnabled) {
      boolean s3Auth = false;
      try {
        // If Request has S3Authentication validate S3 credentials
        // if current OM is leader and then proceed with processing the request.
        if (request.hasS3Authentication()) {
          s3Auth = true;
          checkLeaderStatus();
          S3SecurityUtil.validateS3Credential(request, ozoneManager);
        }
      } catch (IOException ex) {
        // If validate credentials fail return error OM Response.
        return createErrorResponse(request, ex);
      }
      // Check if the request is a read only request
      if (OmUtils.isReadOnly(request)) {
        try {
          if (request.hasS3Authentication()) {
            ozoneManager.setS3Auth(request.getS3Authentication());
          }
          return submitReadRequestToOM(request);
        } finally {
          ozoneManager.setS3Auth(null);
        }
      } else {
        // To validate credentials we have already verified leader status.
        // This will skip of checking leader status again if request has S3Auth.
        if (!s3Auth) {
          checkLeaderStatus();
        }
        try {
          OMClientRequest omClientRequest =
              createClientRequest(request, ozoneManager);
          request = omClientRequest.preExecute(ozoneManager);
        } catch (IOException ex) {
          // As some of the preExecute returns error. So handle here.
          return createErrorResponse(request, ex);
        }
        return submitRequestToRatis(request);
      }
    } else {
      return submitRequestDirectlyToOM(request);
    }
  }

  /**
   * Submits request to OM's Ratis server.
   */
  private OMResponse submitRequestToRatis(OMRequest request)
      throws ServiceException {
    return omRatisServer.submitRequest(request);
  }

  private OMResponse submitReadRequestToOM(OMRequest request)
      throws ServiceException {
    // Check if this OM is the leader.
    RaftServerStatus raftServerStatus = omRatisServer.checkLeaderStatus();
    if (raftServerStatus == LEADER_AND_READY ||
        request.getCmdType().equals(PrepareStatus)) {
      return handler.handleReadRequest(request);
    } else {
      throw createLeaderErrorException(raftServerStatus);
    }
  }

  private ServiceException createLeaderErrorException(
      RaftServerStatus raftServerStatus) {
    if (raftServerStatus == NOT_LEADER) {
      return createNotLeaderException();
    } else {
      return createLeaderNotReadyException();
    }
  }

  private ServiceException createNotLeaderException() {
    RaftPeerId raftPeerId = omRatisServer.getRaftPeerId();

    // TODO: Set suggest leaderID. Right now, client is not using suggest
    // leaderID. Need to fix this.

    OMNotLeaderException notLeaderException =
        new OMNotLeaderException(raftPeerId);

    LOG.debug(notLeaderException.getMessage());

    return new ServiceException(notLeaderException);
  }

  private ServiceException createLeaderNotReadyException() {
    RaftPeerId raftPeerId = omRatisServer.getRaftPeerId();

    OMLeaderNotReadyException leaderNotReadyException =
        new OMLeaderNotReadyException(raftPeerId.toString() + " is Leader " +
            "but not ready to process request yet.");

    LOG.debug(leaderNotReadyException.getMessage());

    return new ServiceException(leaderNotReadyException);
  }

  /**
   * Submits request directly to OM.
   */
  private OMResponse submitRequestDirectlyToOM(OMRequest request) {
    OMClientResponse omClientResponse = null;
    long index = 0L;
    try {
      // If Request has S3Authentication validate S3 credentials and
      // then proceed with processing the request.
      if (request.hasS3Authentication()) {
        S3SecurityUtil.validateS3Credential(request, ozoneManager);
      }
      if (OmUtils.isReadOnly(request)) {
        try {
          if (request.hasS3Authentication()) {
            ozoneManager.setS3Auth(request.getS3Authentication());
          }
          return handler.handleReadRequest(request);
        } finally {
          ozoneManager.setS3Auth(null);
        }
      } else {
        OMClientRequest omClientRequest =
            createClientRequest(request, ozoneManager);
        request = omClientRequest.preExecute(ozoneManager);
        index = transactionIndex.incrementAndGet();
        omClientResponse = handler.handleWriteRequest(request, index);
      }
    } catch (IOException ex) {
      // As some of the preExecute returns error. So handle here.
      return createErrorResponse(request, ex);
    }
    try {
      omClientResponse.getFlushFuture().get();
      if (LOG.isTraceEnabled()) {
        LOG.trace("Future for {} is completed", request);
      }
    } catch (ExecutionException | InterruptedException ex) {
      // terminate OM. As if we are in this stage means, while getting
      // response from flush future, we got an exception.
      String errorMessage = "Got error during waiting for flush to be " +
          "completed for " + "request" + request.toString();
      ExitUtils.terminate(1, errorMessage, ex, LOG);
      Thread.currentThread().interrupt();
    }
    return omClientResponse.getOMResponse();
  }

  private void checkLeaderStatus() throws ServiceException {
    OzoneManagerRatisUtils.checkLeaderStatus(omRatisServer.checkLeaderStatus(),
        omRatisServer.getRaftPeerId());
  }

  /**
   * Create OMResponse from the specified OMRequest and exception.
   *
   * @param omRequest
   * @param exception
   * @return OMResponse
   */
  private OMResponse createErrorResponse(
      OMRequest omRequest, IOException exception) {
    // Added all write command types here, because in future if any of the
    // preExecute is changed to return IOException, we can return the error
    // OMResponse to the client.
    OMResponse.Builder omResponse = OMResponse.newBuilder()
        .setStatus(OzoneManagerRatisUtils.exceptionToResponseStatus(exception))
        .setCmdType(omRequest.getCmdType())
        .setTraceID(omRequest.getTraceID())
        .setSuccess(false);
    if (exception.getMessage() != null) {
      omResponse.setMessage(exception.getMessage());
    }
    return omResponse.build();
  }

  public void stop() {
    if (!isRatisEnabled) {
      ozoneManagerDoubleBuffer.stop();
    }
  }

  public static Logger getLog() {
    return LOG;
  }
}
