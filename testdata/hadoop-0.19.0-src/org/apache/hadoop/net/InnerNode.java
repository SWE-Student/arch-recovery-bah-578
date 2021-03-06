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
/** The class represents a cluster of computer with a tree hierarchical
 * network topology.
 * For example, a cluster may be consists of many data centers filled 
 * with racks of computers.
 * In a network topology, leaves represent data nodes (computers) and inner
 * nodes represent switches/routers that manage traffic in/out of data centers
 * or racks.  
 * 
 */
package org.apache.hadoop.net;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

private class InnerNode extends NodeBase {
    private ArrayList<Node> children=new ArrayList<Node>();
    private int numOfLeaves;
        
    /** Construct an InnerNode from a path-like string */
    InnerNode(String path) {
      super(path);
    }
        
    /** Construct an InnerNode from its name and its network location */
    InnerNode(String name, String location) {
      super(name, location);
    }
        
    /** Construct an InnerNode
     * from its name, its network location, its parent, and its level */
    InnerNode(String name, String location, InnerNode parent, int level) {
      super(name, location, parent, level);
    }
        
    /** Get its children */
    Collection<Node> getChildren() {return children;}
        
    /** Return the number of children this node has */
    int getNumOfChildren() {
      return children.size();
    }
        
    /** Judge if this node represents a rack 
     * Return true if it has no child or its children are not InnerNodes
     */ 
    boolean isRack() {
      if (children.isEmpty()) {
        return true;
      }
            
      Node firstChild = children.get(0);
      if (firstChild instanceof InnerNode) {
        return false;
      }
            
      return true;
    }
        
    /** Judge if this node is an ancestor of node <i>n</i>
     * 
     * @param n a node
     * @return true if this node is an ancestor of <i>n</i>
     */
    boolean isAncestor(Node n) {
      return getPath(this).equals(NodeBase.PATH_SEPARATOR_STR) ||
        (n.getNetworkLocation()+NodeBase.PATH_SEPARATOR_STR).
        startsWith(getPath(this)+NodeBase.PATH_SEPARATOR_STR);
    }
        
    /** Judge if this node is the parent of node <i>n</i>
     * 
     * @param n a node
     * @return true if this node is the parent of <i>n</i>
     */
    boolean isParent(Node n) {
      return n.getNetworkLocation().equals(getPath(this));
    }
        
    /* Return a child name of this node who is an ancestor of node <i>n</i> */
    private String getNextAncestorName(Node n) {
      if (!isAncestor(n)) {
        throw new IllegalArgumentException(
                                           this + "is not an ancestor of " + n);
      }
      String name = n.getNetworkLocation().substring(getPath(this).length());
      if (name.charAt(0) == PATH_SEPARATOR) {
        name = name.substring(1);
      }
      int index=name.indexOf(PATH_SEPARATOR);
      if (index !=-1)
        name = name.substring(0, index);
      return name;
    }
        
    /** Add node <i>n</i> to the subtree of this node 
     * @param n node to be added
     * @return true if the node is added; false otherwise
     */
    boolean add(Node n) {
      if (!isAncestor(n))
        throw new IllegalArgumentException(n.getName()+", which is located at "
                +n.getNetworkLocation()+", is not a decendent of "
                +getPath(this));
      if (isParent(n)) {
        // this node is the parent of n; add n directly
        n.setParent(this);
        n.setLevel(this.level+1);
        for(int i=0; i<children.size(); i++) {
          if (children.get(i).getName().equals(n.getName())) {
            children.set(i, n);
            return false;
          }
        }
        children.add(n);
        numOfLeaves++;
        return true;
      } else {
        // find the next ancestor node
        String parentName = getNextAncestorName(n);
        InnerNode parentNode = null;
        for(int i=0; i<children.size(); i++) {
          if (children.get(i).getName().equals(parentName)) {
            parentNode = (InnerNode)children.get(i);
            break;
          }
        }
        if (parentNode == null) {
          // create a new InnerNode
          parentNode = new InnerNode(parentName, getPath(this),
                                     this, this.getLevel()+1);
          children.add(parentNode);
        }
        // add n to the subtree of the next ancestor node
        if (parentNode.add(n)) {
          numOfLeaves++;
          return true;
        } else {
          return false;
        }
      }
    }
        
    /** Remove node <i>n</i> from the subtree of this node
     * @param n node to be deleted 
     * @return true if the node is deleted; false otherwise
     */
    boolean remove(Node n) {
      String parent = n.getNetworkLocation();
      String currentPath = getPath(this);
      if (!isAncestor(n))
        throw new IllegalArgumentException(n.getName()
                                           +", which is located at "
                                           +parent+", is not a descendent of "+currentPath);
      if (isParent(n)) {
        // this node is the parent of n; remove n directly
        for(int i=0; i<children.size(); i++) {
          if (children.get(i).getName().equals(n.getName())) {
            children.remove(i);
            numOfLeaves--;
            n.setParent(null);
            return true;
          }
        }
        return false;
      } else {
        // find the next ancestor node: the parent node
        String parentName = getNextAncestorName(n);
        InnerNode parentNode = null;
        int i;
        for(i=0; i<children.size(); i++) {
          if (children.get(i).getName().equals(parentName)) {
            parentNode = (InnerNode)children.get(i);
            break;
          }
        }
        if (parentNode==null) {
          return false;
        }
        // remove n from the parent node
        boolean isRemoved = parentNode.remove(n);
        // if the parent node has no children, remove the parent node too
        if (isRemoved) {
          if (parentNode.getNumOfChildren() == 0) {
            children.remove(i);
          }
          numOfLeaves--;
        }
        return isRemoved;
      }
    } // end of remove
        
    /** Given a node's string representation, return a reference to the node */ 
    private Node getLoc(String loc) {
      if (loc == null || loc.length() == 0) return this;
            
      String[] path = loc.split(PATH_SEPARATOR_STR, 2);
      Node childnode = null;
      for(int i=0; i<children.size(); i++) {
        if (children.get(i).getName().equals(path[0])) {
          childnode = children.get(i);
        }
      }
      if (childnode == null) return null; // non-existing node
      if (path.length == 1) return childnode;
      if (childnode instanceof InnerNode) {
        return ((InnerNode)childnode).getLoc(path[1]);
      } else {
        return null;
      }
    }
        
    /** get <i>leafIndex</i> leaf of this subtree 
     * if it is not in the <i>excludedNode</i>*/
    private Node getLeaf(int leafIndex, Node excludedNode) {
      int count=0;
      // check if the excluded node a leaf
      boolean isLeaf =
        excludedNode == null || !(excludedNode instanceof InnerNode);
      // calculate the total number of excluded leaf nodes
      int numOfExcludedLeaves =
        isLeaf ? 1 : ((InnerNode)excludedNode).getNumOfLeaves();
      if (isRack()) { // children are leaves
        if (isLeaf) { // excluded node is a leaf node
          int excludedIndex = children.indexOf(excludedNode);
          if (excludedIndex != -1 && leafIndex >= 0) {
            // excluded node is one of the children so adjust the leaf index
            leafIndex = leafIndex>=excludedIndex ? leafIndex+1 : leafIndex;
          }
        }
        // range check
        if (leafIndex<0 || leafIndex>=this.getNumOfChildren()) {
          return null;
        }
        return children.get(leafIndex);
      } else {
        for(int i=0; i<children.size(); i++) {
          InnerNode child = (InnerNode)children.get(i);
          if (excludedNode == null || excludedNode != child) {
            // not the excludedNode
            int numOfLeaves = child.getNumOfLeaves();
            if (excludedNode != null && child.isAncestor(excludedNode)) {
              numOfLeaves -= numOfExcludedLeaves;
            }
            if (count+numOfLeaves > leafIndex) {
              // the leaf is in the child subtree
              return child.getLeaf(leafIndex-count, excludedNode);
            } else {
              // go to the next child
              count = count+numOfLeaves;
            }
          } else { // it is the excluededNode
            // skip it and set the excludedNode to be null
            excludedNode = null;
          }
        }
        return null;
      }
    }
        
    int getNumOfLeaves() {
      return numOfLeaves;
    }
  }