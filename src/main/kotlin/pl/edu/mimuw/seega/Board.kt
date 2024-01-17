package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_INDENT
import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_SPACING
import pl.edu.mimuw.seega.Constants.Companion.ROW_INDENT

class Board(val size: Int) {
    private val fields: Array<Array<PawnColor>> =
        Array(size) { Array(size) { PawnColor.EMPTY } }.also { it[size / 2][size / 2] = PawnColor.STAR }
    var blackPawns: Int = 0
        private set
    var whitePawns: Int = 0
        private set

    fun placePawn(col: Char, row: Int, pawnColor: PawnColor) {
        fields[rowToIndex(row)][colToIndex(col)] = pawnColor
        changePawnsCount(pawnColor, 1)
    }

    fun removePawn(col: Char, row: Int) {
        val prevPawnColor = fields[rowToIndex(row)][colToIndex(col)]
        fields[rowToIndex(row)][colToIndex(col)] = PawnColor.EMPTY
        changePawnsCount(prevPawnColor, -1)
    }

    fun movePawnAndGetNewField(col: Char, row: Int, direction: Direction): Pair<Char, Int> {
        val fieldColor = fields[rowToIndex(row)][colToIndex(col)]
        val newCol = col + direction.col
        val newRow = row + direction.row

        removePawn(col, row)
        placePawn(newCol, newRow, fieldColor)
        return newCol to newRow
    }

    fun takeOpponentPawnsAndGetResult(newCol: Char, newRow: Int): Boolean {
        var takenPawns = false

        for (direction in Direction.entries) {
            takenPawns = takenPawns or takeOpponentPawn(newCol, newRow, direction)
        }

        return takenPawns
    }

    fun isFieldEmpty(col: Char, row: Int): Boolean {
        return fields[rowToIndex(row)][colToIndex(col)] == PawnColor.EMPTY
    }

    fun isFieldInBounds(col: Char, row: Int): Boolean {
        return col in 'a'..<'a' + size && row in 1..size
    }

    fun isMiddleField(col: Char, row: Int): Boolean {
        return rowToIndex(row) == size / 2 && colToIndex(col) == size / 2
    }

    fun getFieldColor(col: Char, row: Int): PawnColor {
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

    private fun takeOpponentPawn(col: Char, row: Int, direction: Direction): Boolean {
        val fieldColor = fields[rowToIndex(row)][colToIndex(col)]
        val adjacentCol = col + direction.col
        val adjacentRow = row + direction.row

        val nextAdjacentCol = adjacentCol + direction.col
        val nextAdjacentRow = adjacentRow + direction.row

        if (!isFieldInBounds(adjacentCol, adjacentRow) || isMiddleField(adjacentCol, adjacentRow) ||
            fields[rowToIndex(adjacentRow)][colToIndex(adjacentCol)] != PawnColor.getOppositeColor(fieldColor)
        )
            return false

        if (!isFieldInBounds(nextAdjacentCol, nextAdjacentRow) ||
            fields[rowToIndex(nextAdjacentRow)][colToIndex(nextAdjacentCol)] != fieldColor
        )
            return false

        removePawn(adjacentCol, adjacentRow)
        return true
    }

    private fun changePawnsCount(pawnColor: PawnColor, change: Int) {
        if (pawnColor == PawnColor.WHITE)
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