package com.company.graph;

public class Main {
    public static void main(String[] args) {

        Node node1 = new Node(1);
        Node node2 = new Node(2);
        Node node3 = new Node(3);
        Node node4 = new Node(4);
        Node node5 = new Node(5);
        Node node6 = new Node(6);
        Node node7 = new Node(7);

        Graph graph = new Graph();
        graph.addNode(node1);
        graph.addNode(node2);
        graph.addNode(node3);
        graph.addNode(node4);
        graph.addNode(node5);
        graph.addNode(node6);
        graph.addNode(node7);

        graph.addEdge(node1, node2);
        graph.addEdge(node2, node6);
        graph.addEdge(node1, node3);
        graph.addEdge(node3, node5);
        graph.addEdge(node4, node7);
        graph.addEdge(node3, node7);
        graph.printGraph();
        System.out.println("Shortest path: " + graph.findShortestPath(node1, node4));

        Graph graphEuler = new Graph();
        graphEuler.addNode(node1);
        graphEuler.addNode(node2);
        graphEuler.addNode(node3);
        graphEuler.addNode(node4);
        graphEuler.addNode(node5);
//
//        graphEuler.addEdge(node1, node3);
//        graphEuler.addEdge(node1, node2);
//        graphEuler.addEdge(node2, node3);
//        graphEuler.addEdge(node4, node3);
//        graphEuler.addEdge(node4, node5);
//        graphEuler.addEdge(node3, node5);

//        graphEuler.removeNode(node3);

        graphEuler.findEulerianPath();
    }
}
