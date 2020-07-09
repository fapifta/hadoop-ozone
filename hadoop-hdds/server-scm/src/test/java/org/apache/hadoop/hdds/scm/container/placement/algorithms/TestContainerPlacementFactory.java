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
package org.apache.hadoop.hdds.scm.container.placement.algorithms;

import org.apache.hadoop.hdds.conf.ConfigurationSource;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.protocol.DatanodeDetails;
import org.apache.hadoop.hdds.scm.ContainerPlacementStatus;
import org.apache.hadoop.hdds.scm.PlacementPolicy;
import org.apache.hadoop.hdds.scm.net.NetworkTopology;
import org.apache.hadoop.hdds.scm.node.NodeManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.List;

import static org.apache.hadoop.hdds.scm.exceptions.SCMException.ResultCodes.FAILED_TO_INIT_CONTAINER_PLACEMENT_POLICY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;

/**
 * Test for scm container placement factory.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestContainerPlacementFactory
    extends TestScmContainerPlacementPolicyBase {

  @Test
  public void testDefaultPolicyLoads() throws Exception {
    PlacementPolicy policy = configuredPolicy(new OzoneConfiguration());
    assertThat(policy, instanceOf(SCMContainerPlacementRandom.class));
  }

  @Test
  public void testRackAwarePolicyLoads() throws Exception {
    configurePolicy(SCMContainerPlacementRackAware.class);

    PlacementPolicy policy = configuredPolicy();
    assertThat(policy, instanceOf(SCMContainerPlacementRackAware.class));
  }

  @Test
  public void testCapacityPolicyLoads() throws Exception {
    configurePolicy(SCMContainerPlacementCapacity.class);

    PlacementPolicy policy = configuredPolicy();
    assertThat(policy, instanceOf(SCMContainerPlacementCapacity.class));
  }

  @Test
  public void testPolicyClassNotImplemented() throws Exception {
    expectExceptionCausedBy(ClassNotFoundException.class);

    configurePolicy("org.apache.hadoop.DummyClass");

    // instantiate the policy
    configuredPolicy();
  }

  @Test
  public void testExpectedPolicyConstuctorNotFound() throws Exception {
    expectSCMExceptionWith(FAILED_TO_INIT_CONTAINER_PLACEMENT_POLICY);

    configurePolicy(DummyImpl.class);

    // instantiate the policy
    configuredPolicy();
  }

  @Test
  public void testPolicyConsturctorFails() throws Exception {
    expectExceptionCausedBy("Failed to instantiate class");

    configurePolicy(ExcetpionThrowingDummyImpl.class);

    // instantiate the policy
    configuredPolicy();
  }

  /**
   * A dummy container placement implementation for testing.
   */
  protected static class DummyImpl implements PlacementPolicy {

    @Override
    public List<DatanodeDetails> chooseDatanodes(
        List<DatanodeDetails> excludedNodes,
        List<DatanodeDetails> favouredNodes,
        int nodesRequired, long sizeRequired) {
      return null;
    }

    @Override
    public ContainerPlacementStatus
        validateContainerPlacement(List<DatanodeDetails> dns, int replicas) {
      return new ContainerPlacementStatusDefault(1, 1, 1);
    }
  }

  protected static class ExcetpionThrowingDummyImpl extends DummyImpl {

    ExcetpionThrowingDummyImpl(final NodeManager nodeManager,
        final ConfigurationSource conf,
        final NetworkTopology networkTopology, final boolean fallback,
        final SCMContainerPlacementMetrics metrics) {
      throw new RuntimeException();
    }
  }
}
