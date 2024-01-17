package pl.edu.mimuw.seega

enum class PawnColor(private val symbol: Char) {
    EMPTY(' '),
    WHITE('W'),
    BLACK('B'),
    STAR('*');

    override fun toString(): String {
        return symbol.toString()
    }

    companion object {
        fun getOppositeColor(color: PawnColor): PawnColor {
            return if (color == WHITE) BLACK else WHITE
        }
    }
}