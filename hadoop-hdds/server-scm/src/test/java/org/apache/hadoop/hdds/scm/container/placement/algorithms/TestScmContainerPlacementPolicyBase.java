/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdds.scm.container.placement.algorithms;

import org.apache.hadoop.hdds.conf.ConfigurationSource;
import org.apache.hadoop.hdds.protocol.DatanodeDetails;
import org.apache.hadoop.hdds.protocol.DatanodeDetails.Port;
import org.apache.hadoop.hdds.protocol.proto.HddsProtos;
import org.apache.hadoop.hdds.scm.PlacementPolicy;
import org.apache.hadoop.hdds.scm.SCMCommonPlacementPolicy;
import org.apache.hadoop.hdds.scm.container.placement.metrics.SCMNodeMetric;
import org.apache.hadoop.hdds.scm.exceptions.SCMException;
import org.apache.hadoop.hdds.scm.net.NetworkTopology;
import org.apache.hadoop.hdds.scm.node.NodeManager;
import org.apache.hadoop.hdds.scm.node.NodeStatus;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Verifier;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeOperationalState.IN_SERVICE;
import static org.apache.hadoop.hdds.protocol.proto.HddsProtos.NodeState.HEALTHY;
import static org.apache.hadoop.hdds.scm.ScmConfigKeys.OZONE_SCM_CONTAINER_PLACEMENT_IMPL_KEY;
import static org.apache.hadoop.hdds.scm.exceptions.SCMException.ResultCodes
    .FAILED_TO_FIND_HEALTHY_NODES;
import static org.apache.hadoop.hdds.scm.exceptions.SCMException.ResultCodes
    .FAILED_TO_FIND_NODES_WITH_SPACE;
import static org.apache.hadoop.hdds.scm.exceptions.SCMException.ResultCodes
    .FAILED_TO_FIND_SUITABLE_NODE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Bsae class for placement policy tests.
 *
 * Provides utility functions for test setups, and checks for basic assumptions
 * on exceptions should be thrown in error scenarios that are common to all
 * placement policies.
 * NOTE: tests other than default policy test, has to configure the placement
 * policy as test methods defined in this class use the factory to create the
 * tested policy object, and that works based on the configuration.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestScmContainerPlacementPolicyBase {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Rule
  public ContainerPlacementMetricsVerifier metricsVerification =
      ContainerPlacementMetricsVerifier.create();


  /**
   * Common configuration object that the tests can use.
   */
  @Mock
  private ConfigurationSource conf;

  private NodeManager nodeManager;

  private NetworkTopology topology;

  private boolean fallback = false;

  private SCMContainerPlacementMetrics metrics;

  /**
   * Initialize configuration for all tests with default constructor.
   */
  @Before
  public void setup() {
    configurePolicy(SCMContainerPlacementRandom.class);
    metrics = SCMContainerPlacementMetrics.create();
    metricsVerification.verifyOn(metrics);
  }

  /**
   * Test whether the proper exception is thrown in the case when there are
   * no healthy nodes available as returned by the NodeManager instance.
   * @throws Exception
   */
  @Test
  public void testChooseDatanodeWithNoHealthyNodes() throws Exception {
    setupNodeManagerWith(Collections.emptyList());
    setupNodesCapacity(baseMetric(), null);
    PlacementPolicy policy = configuredPolicy();

    expectSCMExceptionWith(FAILED_TO_FIND_HEALTHY_NODES);

    policy.chooseDatanodes(null, null, 3, 10);
  }

  /**
   * Test whether the proper exception is thrown in the case when the number of
   * healthy nodes returned by the NodeManager instance is less then the
   * requested amount of nodes.
   * @throws Exception
   */
  @Test
  public void testChooseDatanodesWithNotEnoughHealthyNodes() throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(2);
    setupNodeManagerWith(nodes);
    setupNodesCapacity(baseMetric(), null);
    PlacementPolicy policy = configuredPolicy();

    expectSCMExceptionWith(FAILED_TO_FIND_SUITABLE_NODE);

    policy.chooseDatanodes(null, null, 3, 10);
  }

  /**
   * Test whether the proper exception is thrown in the case when the number of
   * nodes that have enough space is less then the requested amount of nodes.
   * @throws Exception
   */
  @Test
  public void testChooseDataNodesWithNotEnoughSpaceOnEnoughNodes()
      throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(5);
    setupNodeManagerWith(nodes);
    Map<DatanodeDetails, SCMNodeMetric> capacities = new HashMap<>();
    capacities.put(nodes.get(0), lowFreeSpaceMetric());
    capacities.put(nodes.get(2), lowFreeSpaceMetric());
    capacities.put(nodes.get(4), lowFreeSpaceMetric());
    setupNodesCapacity(baseMetric(), capacities);
    PlacementPolicy policy = configuredPolicy();

    expectSCMExceptionWith(FAILED_TO_FIND_NODES_WITH_SPACE);

    policy.chooseDatanodes(null, null, 3, 40);
  }

  /**
   * Test whether the proper exception is thrown in the case when the number of
   * requested nodes are higher than the number of nodes that are not excluded.
   * @throws Exception
   */
  @Test
  public void testChooseDataNodesWithTooMuchExcludedNodes() throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(4);
    setupNodeManagerWith(nodes);
    List<DatanodeDetails> excludedNodes = new ArrayList<>(nodes);
    excludedNodes.remove(3);
    excludedNodes.remove(1);
    setupNodesCapacity(baseMetric(), null);
    PlacementPolicy policy = configuredPolicy();

    expectSCMExceptionWith(FAILED_TO_FIND_SUITABLE_NODE);

    policy.chooseDatanodes(excludedNodes, null, 3, 40);
  }

  /**
   * Test whether the proper exception is thrown when all nodes are excluded.
   * @throws Exception
   */
  @Test
  public void testChooseDataNodesWithExcludingAllNodes() throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(4);
    setupNodeManagerWith(nodes);
    setupNodesCapacity(baseMetric(), null);
    PlacementPolicy policy = configuredPolicy();

    expectSCMExceptionWith(FAILED_TO_FIND_HEALTHY_NODES);

    policy.chooseDatanodes(nodes, null, 3, 40);
  }

  @Test
  public void testCommonImplementationWithFaultyPolicy()
      throws Exception {
    expectSCMExceptionWith(FAILED_TO_FIND_SUITABLE_NODE);

    List<DatanodeDetails> nodes = createSomeDatanodeDetails(3);
    setupNodeManagerWith(nodes);
    setupNodesCapacity(baseMetric(), null);

    SCMCommonPlacementPolicy policy = new SCMCommonPlacementPolicy(nodeManager, conf)
    {
      @Override
      public DatanodeDetails chooseNode(
          List<DatanodeDetails> healthyNodes) {
        return null;
      }
    };

    policy.getResultSet(3, nodes);
  }

  /**
   * Configures the given class as the placement policy implementation to be
   * returned by the factory.
   * @param clazz the class of the placement policy to be tested.
   */
  protected void configurePolicy(Class<? extends PlacementPolicy> clazz) {
    conf = mock(ConfigurationSource.class);
    doReturn(clazz.getCanonicalName())
        .when(conf).get(OZONE_SCM_CONTAINER_PLACEMENT_IMPL_KEY);
    doReturn(clazz).when(conf).getClass(
        OZONE_SCM_CONTAINER_PLACEMENT_IMPL_KEY,
        SCMContainerPlacementRandom.class,
        PlacementPolicy.class
    );
  }

  protected void configurePolicy(String className) {
    conf = mock(ConfigurationSource.class);
    doReturn(className).when(conf).get(OZONE_SCM_CONTAINER_PLACEMENT_IMPL_KEY);
    try {
      Class<?> clazz = Class.forName(className);
      doReturn(clazz).when(conf).getClass(
          OZONE_SCM_CONTAINER_PLACEMENT_IMPL_KEY,
          SCMContainerPlacementRandom.class,
          PlacementPolicy.class
      );
    } catch (Exception e) {
      // using doThrow.when here seems to fail in IDEA when running all
      // tests in this package
      when(conf.getClass(
          OZONE_SCM_CONTAINER_PLACEMENT_IMPL_KEY,
          SCMContainerPlacementRandom.class,
          PlacementPolicy.class
      )).thenThrow(new RuntimeException(e));
    }
  }

  protected PlacementPolicy configuredPolicy() throws SCMException {
    return ContainerPlacementPolicyFactory
        .getPolicy(conf, nodeManager, topology, fallback, metrics);
  }

  protected PlacementPolicy configuredPolicy(ConfigurationSource conf)
      throws SCMException {
    return ContainerPlacementPolicyFactory
        .getPolicy(conf, nodeManager, topology, fallback, metrics);
  }

  /**
   * Creates and set up the internal nodeManager mock, to return the given
   * list of DatanodeDetails as the healthy nodes.
   * @param nodeLists
   */
  protected void setupNodeManagerWith(List<DatanodeDetails>... nodeLists) {
    nodeManager = mock(NodeManager.class);

    List<DatanodeDetails> healthyNodes =
        Arrays.asList(nodeLists).stream()
            .flatMap(List::stream).collect(Collectors.toList());

    doReturn(new ArrayList<>(healthyNodes))
        .when(nodeManager).getNodes(NodeStatus.inServiceHealthy());
  }

  protected void setFallback() {
    fallback = true;
  }

  protected static SCMNodeMetric emptyNodeMetric(){
    return new SCMNodeMetric(200, 0, 200);
  }

  /**
   * Creates an {@link SCMNodeMetric} instance with the following space metrics.
   * capacity = 200;
   * used = 100;
   * remaining = 100
   * @return SCMNodemetric instance with capacity=200; used=100; remaining=100;
   */
  protected static SCMNodeMetric baseMetric() {
    return new SCMNodeMetric(200, 100, 100);
  }

  protected static SCMNodeMetric utilizedNodeMetric(){
    return  new SCMNodeMetric(200, 140, 60);
  }

  protected static SCMNodeMetric heavilyUtilizedNodeMetric(){
    return new SCMNodeMetric(200, 160, 40);
  }

  /**
   * Creates an {@link SCMNodeMetric} instance with the following space metrics.
   * capacity = 200;
   * used = 190;
   * remaining = 10
   * @return SCMNodemetric instance with capacity=200; used=190; remaining=10;
   */
  protected static SCMNodeMetric lowFreeSpaceMetric(){
    return new SCMNodeMetric(200, 190, 10);
  }

  /**
   * Sets up the internal NodeManager instance to return the specified node
   * capacity metrics.
   *
   * @param baseMetric the metric that should be returned for any nonspecified
   *                   nodes
   * @param nodeMetrics a map of DatanodeDetails, and SCMNodeMetrics, to specify
   *                    the metrics to be returned for a given Datanode.
   */
  protected void setupNodesCapacity(SCMNodeMetric baseMetric,
      Map<DatanodeDetails, SCMNodeMetric> nodeMetrics){
    doReturn(baseMetric)
        .when(nodeManager).getNodeStat(any(DatanodeDetails.class));

    if (nodeMetrics!=null) {
      for (DatanodeDetails key : nodeMetrics.keySet()) {
        doReturn(nodeMetrics.get(key))
            .when(nodeManager).getNodeStat(key);
      }
    }
  }

  /**
   * Setup the internal thrown ExpectedException rule to expect an SCMException
   * with the given result code, and to fail the test when the result code is
   * not the expected one.
   * @param expectedResultCode the result code to expect
   */
  protected void expectSCMExceptionWith(
      SCMException.ResultCodes expectedResultCode){
    thrown.expect(SCMException.class);
    thrown.expect(new SCMExceptionMatcher(expectedResultCode));
  }

  protected void expectExceptionCausedBy(String msgSubStr) {
    thrown.expect(Throwable.class);
    if (msgSubStr != null) {
      thrown.expectMessage(msgSubStr);
    }
  }

  protected void expectExceptionCausedBy(Class<? extends Throwable> clazz) {
    thrown.expect(Throwable.class);
    if (clazz != null) {
      thrown.expectCause(IsInstanceOf.instanceOf(clazz));
    }
  }

  /**
   * Method to create a list of random DatanodeDetails with the specified
   * node count.
   * @param count the number of nodes in the list
   * @return the list of random DatanodeDetails objects.
   */
  protected List<DatanodeDetails> createSomeDatanodeDetails(int count) {
    List<DatanodeDetails> nodes = new ArrayList<>(count);
    for (int i = 0; i < count; i++){
      DatanodeDetails d = mock(DatanodeDetails.class);
      UUID id = UUID.randomUUID();
      doReturn(id).when(d).getUuid();
      doReturn(id.toString()).when(d).getUuidString();
      doReturn("192.168.1."+i).when(d).getIpAddress();
      doReturn("node"+i).when(d).getHostName();

      Port ratisPort = DatanodeDetails.newPort(Port.Name.RATIS, 1025);
      Port standAlonePort = DatanodeDetails.newPort(Port.Name.STANDALONE, 1026);
      Port restPort = DatanodeDetails.newPort(Port.Name.REST, 1027);
      List<Port> portList = Arrays.asList(ratisPort, standAlonePort, restPort);

      doReturn(portList).when(d).getPorts();
      doReturn(ratisPort).when(d).getPort(Port.Name.RATIS);
      doReturn(standAlonePort).when(d).getPort(Port.Name.STANDALONE);
      doReturn(restPort).when(d).getPort(Port.Name.REST);
      doReturn("node"+i).when(d).getNetworkName();
      when(d.toString()).thenCallRealMethod();

      nodes.add(d);
    }
    return nodes;
  }

  protected void useTopology(NetworkTopology t) {
    topology = t;
  }

  protected void addToTopology(DatanodeDetails node) {
    topology.add(node);
  }

  /**
   * Assert if the given value is within the range defined by low and high.
   *
   * @param low the low boundary of the range, inclusive
   * @param high the high boundary of the range, inclusive
   * @param value the value to be checked
   */
  protected void assertRange(int low, int high, int value){
    assertTrue("Asserting low<=high as "+low+"<="+high, low<=high);
    assertTrue("Asserting low<=value as "+low+"<="+value, low <= value);
    assertTrue("Asserting high>=value as "+high+">="+value, high >= value);
  }

  /**
   * Matcher to use with the internal ExpectedException Rule to check
   * SCMExceptions thrown in various test cases.
   */
  private class SCMExceptionMatcher extends BaseMatcher<SCMException> {

    private SCMException.ResultCodes expectedCode;
    private SCMException.ResultCodes actualCode;

    SCMExceptionMatcher(SCMException.ResultCodes expectedCode) {
      this.expectedCode = expectedCode;
    }

    @Override
    public boolean matches(Object item) {
      if (item instanceof SCMException){
        SCMException e = (SCMException) item;
        actualCode = e.getResult();
        return e.getResult().equals(expectedCode);
      }
      return false;
    }

    @Override
    public void describeTo(Description description) {
      description.appendText("SCMException does not contain the expected "
          + "result code.\n");
      description.appendText("    Actual: " + actualCode + "; Expected: "
          + expectedCode);
    }

  }

  /**
   * JUnit Verifier Rule implementation to verify the Metrics reported by
   * placement policy implementations during testing.
   * All public instance methods are returning the actual instance for
   * fluid chaining of expectations.
   */
  protected static final class ContainerPlacementMetricsVerifier
      extends Verifier {
    private static final String METRIC_NAME_REQUEST_COUNT = "Request";
    private static final String METRIC_NAME_SUCCESS_COUNT = "Success";
    private static final String METRIC_NAME_FALLBACK_COUNT = "Fallback";
    private static final String METRIC_NAME_ATTEMPT_COUNT = "Attempt";

    private SCMContainerPlacementMetrics metrics;

    private Long expectedRequestCount = 0L;
    private Long expectedSuccessCount = 0L;
    private Long expectedFallbackCount = 0L;
    private Long expectedAttemptCount = 0L;

    private boolean expectGreaterAttemptCount = false;
    private boolean expectGreaterSuccessCount = false;
    private boolean expectGreaterFallbackCount = false;

    private ContainerPlacementMetricsVerifier() {};

    public static ContainerPlacementMetricsVerifier create() {
      return new ContainerPlacementMetricsVerifier();
    }

    @Override
    protected void verify() {
      if (metrics == null){
        return;
      }

      verifyMetric(METRIC_NAME_REQUEST_COUNT, false,
          expectedRequestCount, metrics.getDatanodeRequestCount());
      verifyMetric(METRIC_NAME_SUCCESS_COUNT, expectGreaterSuccessCount,
          expectedSuccessCount, metrics.getDatanodeChooseSuccessCount());
      verifyMetric(METRIC_NAME_FALLBACK_COUNT, expectGreaterFallbackCount,
          expectedFallbackCount, metrics.getDatanodeChooseFallbackCount());
      verifyMetric(METRIC_NAME_ATTEMPT_COUNT, expectGreaterAttemptCount,
          expectedAttemptCount, metrics.getDatanodeChooseAttemptCount());
    }

    private void verifyMetric(
        String metricName, boolean greaterIsOk, long expected, long actual) {
      if (greaterIsOk) {
        assertTrue(metricName + " count metric is less than expected",
            expected <= actual);
      } else {
        assertEquals(metricName + " count metric does not match",
            expected, actual);
      }
    }

    /**
     * Setter to define the metrics object to verify against.
     * @param metricsToVerify the metrics object used during the test.
     */
    public ContainerPlacementMetricsVerifier verifyOn(
        SCMContainerPlacementMetrics metricsToVerify) {
      this.metrics = metricsToVerify;
      return this;
    }

    /**
     * Gives the possibility to skip metrics verification for a given test.
     */
    public ContainerPlacementMetricsVerifier skip() {
      this.metrics = null;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectRequestCount(long count) {
      expectedRequestCount = count;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectSuccessCount(long count) {
      expectedSuccessCount = count;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectFallbackCount(long count) {
      expectedFallbackCount = count;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectAttemptCount(long count) {
      expectedAttemptCount = count;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectMinimumAttemptCount(
        long count) {

      expectedAttemptCount = count;
      expectGreaterAttemptCount = true;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectMinimumSuccessCount(
        long count) {

      expectedSuccessCount = count;
      expectGreaterSuccessCount = true;
      return this;
    }

    public ContainerPlacementMetricsVerifier expectMinimumFallbackCount(
        long count) {

      expectedFallbackCount = count;
      expectGreaterFallbackCount = true;
      return this;
    }
  }
}





