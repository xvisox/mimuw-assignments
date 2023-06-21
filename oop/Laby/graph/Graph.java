package com.company.graph;

import java.util.*;

public class Graph {
    private ArrayList<Node> nodes;

    public Graph() {
        this.nodes = new ArrayList<>();
    }

    public void addNode(Node node) {
        if (!nodes.contains(node)) {
            nodes.add(node);
        }
    }

    public void removeNode(Node node) {
        int size = node.getNeighbours().size();
        if (nodes.contains(node)) {
            for (int i = 0; i < size; i++) {
                node.disconnectNodes(node.getNeighbours().get(0));
            }
        }
        nodes.remove(node);
    }

    public void addEdge(Node node1, Node node2) {
        if (nodes.contains(node1) && nodes.contains(node2)) {
            node1.connectNodes(node2);
        }
    }

    public void removeEdge(Node node1, Node node2) {
        if (nodes.contains(node1) && nodes.contains(node2)) {
            node1.disconnectNodes(node2);
        }
    }

    public int findShortestPath(Node start, Node end) {
        Node currentNode;
        Queue<Node> currentQueue = new ArrayDeque<>();
        Queue<Node> nextQueue = new ArrayDeque<>();
        boolean pathFound = false;
        int resultLength = 0;
        int length = 0;
        currentQueue.add(start);

        Map<Node, Boolean> visited = new HashMap<>();
        for (Node node : this.nodes) {
            visited.put(node, false);
        }

        while ((!currentQueue.isEmpty() || !nextQueue.isEmpty()) && !pathFound) {
            while (!currentQueue.isEmpty()) {
                currentNode = currentQueue.remove();
                if (!visited.get(currentNode)) {
                    if (currentNode.equals(end)) {
                        pathFound = true;
                        resultLength = length;
                    } else {
                        visited.put(currentNode, true);
                        for (Node neighbour : currentNode.getNeighbours()) {
                            if (!visited.get(neighbour)) {
                                nextQueue.add(neighbour);
                            }
                        }
                    }
                }
            }
            length++;
            currentQueue = nextQueue;
            nextQueue = new ArrayDeque<>();
        }
        return resultLength;
    }

    public void printGraph() {
        for (Node node : nodes) {
            System.out.println(node);
        }
    }

    public boolean findEulerianPath() {
        int oddNodes = 0;
        Node startNode = nodes.get(0);
        for (Node node : nodes) {
            if (node.getDegree() % 2 == 1) {
                oddNodes++;
                startNode = node;
            }
        }
        if (oddNodes == 0 || oddNodes == 2) {
            // Here could be a deep copy of this graph.
            printEuler(startNode);
            return true;
        } else {
            System.out.println("Eulerian Path can't be found in this graph.");
            return false;
        }
    }

    private void printEuler(Node startNode) {
        for (int i = 0; i < startNode.getNeighbours().size(); i++) {
            Node v = startNode.getNeighbours().get(i);
            if (isValidNextEdge(startNode, v)) {
                System.out.print(startNode.getId() + "-" + v.getId() + " ");
                removeEdge(startNode, v);
                printEuler(v);
            }
        }
    }

    private boolean isValidNextEdge(Node u, Node v) {
        if (u.getNeighbours().size() == 1) {
            return true;
        }

        boolean[] isVisited = new boolean[this.nodes.size()];
        int count1 = dfsCount(u, isVisited);

        removeEdge(u, v);
        isVisited = new boolean[this.nodes.size()];
        int count2 = dfsCount(u, isVisited);

        addEdge(u, v);
        return count1 <= count2;
    }

    private int dfsCount(Node v, boolean[] isVisited) {
        isVisited[v.getId() - 1] = true;
        int count = 1;
        for (Node node : v.getNeighbours()) {
            if (!isVisited[node.getId() - 1]) {
                count = count + dfsCount(node, isVisited);
            }
        }
        return count;
    }
}
