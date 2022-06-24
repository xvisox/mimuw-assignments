package pl.mimuw.atrybuty.kariera;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypKariera {
    @JsonProperty("rolnik") ROLNIK,
    @JsonProperty("rzemieslnik") RZEMIESLNIK,
    @JsonProperty("inzynier") INZYNIER,
    @JsonProperty("gornik") GORNIK,
    @JsonProperty("programista") PROGRAMISTA
}
