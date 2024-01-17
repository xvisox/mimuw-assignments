package pl.edu.mimuw.seega

enum class Field {
    EMPTY,
    WHITE,
    BLACK,
    STAR;

    companion object {
        fun getOppositeColor(color: Field): Field {
            return if (color == WHITE) BLACK else WHITE
        }
    }
}