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

import org.apache.hadoop.hdds.protocol.DatanodeDetails;
import org.apache.hadoop.hdds.scm.ContainerPlacementStatus;
import org.apache.hadoop.hdds.scm.PlacementPolicy;
import org.apache.hadoop.hdds.scm.container.placement.metrics.SCMNodeMetric;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test for the capacity aware container placement policy:
 * {@link SCMContainerPlacementCapacity}.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestSCMContainerPlacementCapacity
    extends TestScmContainerPlacementPolicyBase{

  /**
   * Configure {@link SCMContainerPlacementCapacity} as the policy.
   */
  @Before
  public void setup(){
    super.setup();
    configurePolicy(SCMContainerPlacementCapacity.class);
  }

  /**
   * Test the placement policy with a few nodes full, and a few excluded with
   * various number of requested nodes.
   * At the end test the distribution of the selections between datanodes,
   * and verify metrics is updated properly.
   * @throws Exception
   */
  @Test
  public void testdistributionOfChoosenDatanodesWithExcludesAndLowSpaceNodes()
      throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(10);
    setupNodeManagerWith(nodes);

    Map<DatanodeDetails, SCMNodeMetric> capacities = new HashMap<>();
    capacities.put(nodes.get(4), lowFreeSpaceMetric());
    capacities.put(nodes.get(6), new SCMNodeMetric(200, 180, 20));
    capacities.put(nodes.get(8), new SCMNodeMetric(200, 160, 40));
    setupNodesCapacity(baseMetric(), capacities);

    PlacementPolicy policy = configuredPolicy();

    List<DatanodeDetails> excludedNodes = new ArrayList<>();
    excludedNodes.add(nodes.get(0));
    excludedNodes.add(nodes.get(2));

    Map<DatanodeDetails, Integer> nodeSelections = new HashMap<>();
    for (DatanodeDetails dn : nodes) {
      nodeSelections.put(dn, 0);
    }
    Random r = new Random();

    for (int i = 0; i < 1000; i++) {
      int requiredNodes = r.nextInt(6) + 1;
      List<DatanodeDetails> selectedNodes =
          policy.chooseDatanodes(excludedNodes, null, requiredNodes, 15);

      Assert.assertEquals(requiredNodes, selectedNodes.size());

      for (DatanodeDetails dn : selectedNodes) {
        nodeSelections.put(dn, nodeSelections.get(dn) + 1);
      }
    }

    // assert excluded nodes were never selected
    assertEquals(0, nodeSelections.get(nodes.get(0)).intValue());
    assertEquals(0, nodeSelections.get(nodes.get(2)).intValue());
    // assert node with less space then required is never selected
    assertEquals(0, nodeSelections.get(nodes.get(4)).intValue());

    // base utilization nodes average selection count
    int avg = (nodeSelections.get(nodes.get(1))
        + nodeSelections.get(nodes.get(3))
        + nodeSelections.get(nodes.get(5))
        + nodeSelections.get(nodes.get(7))
        + nodeSelections.get(nodes.get(9))) / 5;
    // for explanation see same threshold in random placement policy test
    int threshold = 75;
    int expectedMin = avg - threshold;
    int expectedMax = avg + threshold;

    // we expect 2 low space nodes were selected less often than the average
    assertRange(0, expectedMin, nodeSelections.get(nodes.get(6)));
    assertRange(0, expectedMin, nodeSelections.get(nodes.get(8)));
    // from the low space nodes we expect less selection for the one that has
    // less space.
    assertTrue(
        nodeSelections.get(nodes.get(6)) < nodeSelections.get(nodes.get(8))
    );

    // roughly equal distribution is expected on other nodes
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(1)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(3)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(5)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(7)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(9)));

    //TODO: metricsCheck
  }


  @Test
  public void testChooseThreeNodesFromThreeNodes() throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(3);
    setupNodeManagerWith(nodes);
    setupNodesCapacity(baseMetric(), null);
    PlacementPolicy policy = configuredPolicy();

    int requiredNodes = 3;
    List<DatanodeDetails> selectedNodes =
        policy.chooseDatanodes(null, null, requiredNodes, 15);

    assertEquals(requiredNodes, selectedNodes.size());
    assertArrayEquals(nodes.toArray(), selectedNodes.toArray());
  }

  // placement validations have to conform the same rules as with
  // the random placement policy.
  // this test is about placement not about replica counts!
  @Test
  public void testThreeReplicaSatisfiesPolicyAndHasAllReplicas()
      throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(3);

    setupNodeManagerWith(nodes);

    PlacementPolicy policy = configuredPolicy();
    ContainerPlacementStatus placementStatus =
        policy.validateContainerPlacement(nodes, 3);

    assertTrue(placementStatus.isPolicySatisfied());
    assertEquals(0, placementStatus.misReplicationCount());
  }

  // this test is about placement not about replica counts!
  @Test
  public void
      testZeroReplicaDoesNotSatisfyPolicyAndOneReplicaNeededToSatisfyPlacement()
      throws Exception {
    List<DatanodeDetails> noNodes = createSomeDatanodeDetails(0);
    setupNodeManagerWith(noNodes);

    PlacementPolicy policy = configuredPolicy();
    ContainerPlacementStatus placementStatus =
        policy.validateContainerPlacement(noNodes, 3);

    assertFalse(placementStatus.isPolicySatisfied());
    assertEquals(1, placementStatus.misReplicationCount());
  }

  // this test is about placement not about replica counts!
  @Test
  public void
      testOneReplicaSatisfyPolicyAndNoReplicaIsNeededToSatisfyPlacement()
      throws Exception {
    List<DatanodeDetails> nodes = createSomeDatanodeDetails(1);
    setupNodeManagerWith(nodes);

    PlacementPolicy policy = configuredPolicy();
    ContainerPlacementStatus placementStatus =
        policy.validateContainerPlacement(nodes, 3);

    assertTrue(placementStatus.isPolicySatisfied());
    assertEquals(0, placementStatus.misReplicationCount());
  }
}