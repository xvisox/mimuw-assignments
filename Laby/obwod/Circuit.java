package com.company.obwod;

import java.util.ArrayList;

public class Circuit {
    private Gate outputGate;
    private ArrayList<Gate> gates;

    public Circuit(Gate outputGate) {
        this.outputGate = outputGate;
        this.gates = new ArrayList<>();
    }

    public boolean evaluate(ArrayList<Boolean> input) {
        InputGate inTrue = new TrueGate();
        InputGate inFalse = new FalseGate();

        for (Gate gate : gates) {
            if (gate.getInputGates().size() == 0) {
                for (int i = 0; i < 2; i++) {
                    if (input.remove(0)) gate.getInputGates().add(inTrue);
                    else gate.getInputGates().add(inFalse);
                }
            }
        }
        return outputGate.getValue();
    }

    public void addGate(Gate gate) {
        gates.add(gate);
    }
}
