package com.company.graph;

import java.util.ArrayList;

public class Node {
    private int id;
    private ArrayList<Node> neighbours;

    public Node(int id) {
        this.id = id;
        this.neighbours = new ArrayList<Node>();
    }

    public void connectNodes(Node node) {
        neighbours.add(node);
        node.getNeighbours().add(this);
    }

    public void disconnectNodes(Node node) {
        neighbours.remove(node);
        node.getNeighbours().remove(this);
    }

    public int getId() {
        return id;
    }

    public ArrayList<Node> getNeighbours() {
        return neighbours;
    }

    public int getDegree() {
        return neighbours.size();
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (Node node : neighbours) {
            stringBuilder.append(' ');
            stringBuilder.append(node.getId());
        }
        return "Node " + id + " |  Neighbours:" + stringBuilder;
    }
}
