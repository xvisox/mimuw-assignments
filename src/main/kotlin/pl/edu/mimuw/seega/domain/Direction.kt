package pl.edu.mimuw.seega.domain

enum class Direction(val col: Int, val row: Int) {
    UP(0, -1),
    DOWN(0, 1),
    LEFT(-1, 0),
    RIGHT(1, 0);
}