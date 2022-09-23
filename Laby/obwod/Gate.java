package com.company.obwod;

import java.util.ArrayList;

public abstract class Gate {
    protected Boolean value;
    protected ArrayList<Gate> inputGates;

    public Gate() {
        this.value = null;
        this.inputGates = new ArrayList<>();
    }

    public boolean getValue() {
        if (value == null) setValue(inputGates);
        return value;
    }

    public abstract void setValue(ArrayList<Gate> gates);

    public void addInputGate(Gate gate) {
        inputGates.add(gate);
    }

    public ArrayList<Gate> getInputGates() {
        return inputGates;
    }

    @Override
    public String toString() {
        return "Gate{" +
                "value=" + value +
                '}';
    }
}
