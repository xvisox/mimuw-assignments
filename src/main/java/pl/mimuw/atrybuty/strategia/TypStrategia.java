package pl.mimuw.atrybuty.strategia;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypStrategia {
    @JsonProperty("sredni") SREDNI,
    @JsonProperty("wypukly") WYPUKLY,
    @JsonProperty("regulujacy") REGULUJACY

}
