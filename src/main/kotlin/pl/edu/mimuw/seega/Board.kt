package pl.edu.mimuw.seega

class Board(
    private val size: Int,
) {
    private val fields: Array<Array<Char>> = Array(size) { Array(size) { ' ' } }.also { it[size / 2][size / 2] = '*' }
    private var spaceLeft: Int = size * size - 1

    fun placePawn(col: Char, row: Int, color: Char) {
        fields[row - 1][col - 'a'] = color
        spaceLeft--
    }

    fun isFieldInBounds(col: Char, row: Int): Boolean {
        return col in 'a'..<'a' + size && row in 1..size
    }

    fun isFieldEmpty(col: Char, row: Int): Boolean {
        return fields[row - 1][col - 'a'] == ' '
    }

    fun isFull(): Boolean {
        return spaceLeft == 0
    }

    override fun toString(): String {
        val stringBuilder = StringBuilder()

        stringBuilder.append(Constants.FIRST_ROW_INDENT)
        for (i in 0 until size) {
            stringBuilder.append("${('a' + i)}${Constants.FIRST_ROW_SPACING}")
        }

        stringBuilder.appendRowSeparator(size)
        for (i in fields.indices) {
            stringBuilder.append(" ${i + 1} |")
            for (j in fields[i].indices) {
                stringBuilder.append(" ${fields[i][j]} |")
            }
            stringBuilder.appendRowSeparator(size)
        }

        return stringBuilder.toString()
    }

    private fun StringBuilder.appendRowSeparator(size: Int) {
        append("\n" + Constants.ROW_INDENT + "+---".repeat(size) + "+\n")
    }
}