package com.company.obwod;

import java.util.ArrayList;

public class OrGate extends Gate {

    @Override
    public void setValue(ArrayList<Gate> gates) {
        boolean result = false;
        for (Gate gate : gates) {
            result = result || gate.getValue();
        }
        value = result;
    }
}
