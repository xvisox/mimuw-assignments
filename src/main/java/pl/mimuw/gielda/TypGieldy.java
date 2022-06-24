package pl.mimuw.gielda;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypGieldy {
    @JsonProperty("socjalistyczna") SOCJALISTYCZNA,
    @JsonProperty("kapitalistyczna") KAPITALISTYCZNA,
    @JsonProperty("zrownowazona") ZROWNOWAZONA
}
