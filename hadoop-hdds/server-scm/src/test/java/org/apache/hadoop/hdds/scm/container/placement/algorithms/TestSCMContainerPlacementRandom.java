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
 * Tests for the random container placement policy implementation.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestSCMContainerPlacementRandom
    extends TestScmContainerPlacementPolicyBase {

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
    capacities.put(nodes.get(2), lowFreeSpaceMetric());
    capacities.put(nodes.get(5), lowFreeSpaceMetric());
    capacities.put(nodes.get(7), lowFreeSpaceMetric());
    setupNodesCapacity(baseMetric(), capacities);

    List<DatanodeDetails> excludedNodes = new ArrayList<>(2);
    excludedNodes.add(nodes.get(0));
    excludedNodes.add(nodes.get(1));

    PlacementPolicy policy = configuredPolicy();

    Map<DatanodeDetails, Integer> nodeSelections = new HashMap<>();
    for (int i = 0; i < nodes.size(); i++) {
      nodeSelections.put(nodes.get(i), 0);
    }
    Random r = new Random();
    for (int i = 0; i < 1000; i++) {
      int requiredNodes = r.nextInt(4)+1;
      List<DatanodeDetails> selectedNodes =
          policy.chooseDatanodes(excludedNodes, null, requiredNodes, 15);

      assertEquals(requiredNodes, selectedNodes.size());

      for (DatanodeDetails dn : selectedNodes) {
        nodeSelections.put(dn, nodeSelections.get(dn) + 1);
      }
    }

    // excluded nodes
    assertEquals(0, nodeSelections.get(nodes.get(0)).intValue());
    assertEquals(0, nodeSelections.get(nodes.get(1)).intValue());
    assertEquals(0, nodeSelections.get(nodes.get(2)).intValue());
    assertEquals(0, nodeSelections.get(nodes.get(5)).intValue());
    assertEquals(0, nodeSelections.get(nodes.get(7)).intValue());

    int avg = (nodeSelections.get(nodes.get(3))
        + nodeSelections.get(nodes.get(4))
        + nodeSelections.get(nodes.get(6))
        + nodeSelections.get(nodes.get(8))
        + nodeSelections.get(nodes.get(9))) / 5;
    // empirical value determined based on 30k test runs
    // the furthest we got from average in this 30k runs is 54
    // so with this threshold value we should not see flakiness anytime soon.
    int threshold = 75;
    int expectedMin = avg - threshold;
    int expectedMax = avg + threshold;

    // roughly equal distribution is expected on all nodes
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(3)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(4)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(6)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(8)));
    assertRange(expectedMin, expectedMax, nodeSelections.get(nodes.get(9)));

    metricsVerification.skip();
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