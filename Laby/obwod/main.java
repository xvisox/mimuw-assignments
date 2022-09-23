package com.company.obwod;

import java.util.ArrayList;

public class main {
    public static void main(String[] args) {
        AndGate and1 = new AndGate();
        AndGate and2 = new AndGate();
        AndGate and3 = new AndGate();
        NotGate not1 = new NotGate();
        NotGate not2 = new NotGate();
        OrGate or1 = new OrGate();

        not1.addInputGate(and1);
        and3.addInputGate(not1);
        and3.addInputGate(or1);
        or1.addInputGate(and2);
        or1.addInputGate(not2);
        // and1.addInputGate(inTrue);
        // and1.addInputGate(inFalse);
        // and2.addInputGate(inTrue);
        // and2.addInputGate(inFalse);
        // not2.addInputGate(inFalse);

        Circuit circuit = new Circuit(and3);
        ArrayList<Boolean> input = new ArrayList<>();
        input.add(true);
        input.add(false);

        input.add(true);
        input.add(false);

        input.add(false);
        input.add(false);

        circuit.addGate(and1);
        circuit.addGate(and2);
        circuit.addGate(and3);
        circuit.addGate(not1);
        circuit.addGate(not2);
        circuit.addGate(or1);

        System.out.println(circuit.evaluate(input));
    }
}
