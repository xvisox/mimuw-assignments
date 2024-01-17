package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_INDENT
import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_SPACING
import pl.edu.mimuw.seega.Constants.Companion.ROW_INDENT

class Board(val size: Int) {
    private val fields: Array<Array<Field>> = Array(size) { Array(size) { Field.EMPTY } }.also { it[size / 2][size / 2] = Field.STAR }
    var blackPawns: Int = 0
        private set
    var whitePawns: Int = 0
        private set

    fun placePawn(col: Char, row: Int, fieldColor: Field) {
        fields[rowToIndex(row)][colToIndex(col)] = fieldColor
        changePawnsCount(fieldColor, 1)
    }

    fun movePawnAndGetNewField(col: Char, row: Int, direction: Direction): Pair<Char, Int> {
        val fieldColor = fields[rowToIndex(row)][colToIndex(col)]
        val newCol = col + direction.col
        val newRow = row + direction.row

        fields[rowToIndex(row)][colToIndex(col)] = Field.EMPTY
        fields[rowToIndex(newRow)][colToIndex(newCol)] = fieldColor
        return newCol to newRow
    }

    fun takeOpponentPawnsAndGetResult(newCol: Char, newRow: Int): Boolean {
        val takenPawns = false
        val fieldColor = fields[rowToIndex(newRow)][colToIndex(newCol)]

        for (direction in Direction.entries) {
            takenPawns or takeOpponentPawn(newCol, newRow, direction, fieldColor)
        }

        return takenPawns
    }

    fun isFieldEmpty(col: Char, row: Int): Boolean {
        return fields[rowToIndex(row)][colToIndex(col)] == Field.EMPTY
    }

    fun isFieldInBounds(col: Char, row: Int): Boolean {
        return col in 'a'..<'a' + size && row in 1..size
    }

    fun getFieldColor(col: Char, row: Int): Field {
        return fields[rowToIndex(row)][colToIndex(col)]
    }

    override fun toString(): String {
        val stringBuilder = StringBuilder()

        stringBuilder.append(FIRST_ROW_INDENT)
        for (i in 0 until size) {
            stringBuilder.append("${('a' + i)}${FIRST_ROW_SPACING}")
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

    private fun takeOpponentPawn(col: Char, row: Int, direction: Direction, fieldColor: Field): Boolean {
        val adjacentCol = col + direction.col
        val adjacentRow = row + direction.row

        val nextAdjacentCol = adjacentCol + direction.col
        val nextAdjacentRow = adjacentRow + direction.row

        if (!isFieldInBounds(adjacentCol, adjacentRow) ||
            fields[rowToIndex(adjacentRow)][colToIndex(adjacentCol)] == fieldColor
        )
            return false

        if (!isFieldInBounds(nextAdjacentCol, nextAdjacentRow) ||
            fields[rowToIndex(nextAdjacentRow)][colToIndex(nextAdjacentCol)] != fieldColor
        )
            return false

        fields[rowToIndex(adjacentRow)][colToIndex(adjacentCol)] = Field.EMPTY
        changePawnsCount(Field.getOppositeColor(fieldColor), -1)
        return true
    }

    private fun changePawnsCount(fieldColor: Field, change: Int) {
        if (fieldColor == Field.WHITE)
            whitePawns += change
        else
            blackPawns += change
    }

    private fun colToIndex(col: Char): Int {
        return col - 'a'
    }

    private fun rowToIndex(row: Int): Int {
        return row - 1
    }

    private fun StringBuilder.appendRowSeparator(size: Int) {
        append("\n" + ROW_INDENT + "+---".repeat(size) + "+\n")
    }
}