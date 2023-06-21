package com.company.kolokwia.szczepienia;

import java.util.HashMap;
import java.util.Map;

public class Wojewodztwa {
    private Map<Integer, Wojewodztwo> wojewodztwa;

    public Wojewodztwa() {
        wojewodztwa = new HashMap<>();
    }

    public Wojewodztwo getWojewodztwo(Integer id) {
        return wojewodztwa.get(id);
    }
}
