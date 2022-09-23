package pl.mimuw.atrybuty.kupowanie;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypKupowanie {
    @JsonProperty("technofob") TECHNOFOB,
    @JsonProperty("czyscioszek") CZYSCIOSZEK,
    @JsonProperty("zmechanizowany") ZMECHANIZOWANY,
    @JsonProperty("gadzeciarz") GADZECIARZ
}
