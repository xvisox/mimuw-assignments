package com.company.obwod;

import java.util.ArrayList;

public class AndGate extends Gate {

    @Override
    public void setValue(ArrayList<Gate> gates) {
        boolean result = true;
        for (Gate gate : gates) {
            result = result && gate.getValue();
        }
        value = result;
    }
}
