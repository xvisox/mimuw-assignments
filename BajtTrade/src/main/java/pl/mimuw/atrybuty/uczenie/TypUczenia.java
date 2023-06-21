package pl.mimuw.atrybuty.uczenie;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypUczenia {
    @JsonProperty("student") STUDENT,
    @JsonProperty("okresowy") OKRESOWY,
    @JsonProperty("pracus") PRACUS,
    @JsonProperty("oszczedny") OSZCZEDNY,
    @JsonProperty("rozkladowy") ROZKLADOWY
}
