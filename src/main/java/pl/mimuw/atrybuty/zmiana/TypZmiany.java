package pl.mimuw.atrybuty.zmiana;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypZmiany {
    @JsonProperty("rewolucjonista") REWOLUCJONISTA,
    @JsonProperty("konserwatysta") KONSERWATYSTA
}
