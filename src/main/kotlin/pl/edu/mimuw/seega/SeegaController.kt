package pl.edu.mimuw.seega

class SeegaController(private val board: Board) {
    private var currentColor: Char = Constants.WHITE

    fun executeDeploy(col: Char, row: Int) {
        if (!board.isFieldInBounds(col, row)) throw Exception("Field is out of bounds.")
        if (!board.isFieldEmpty(col, row)) throw Exception("Field is not empty.")
        board.placePawn(col, row, currentColor)
    }

    fun executeMove(): Unit = TODO()

    fun isPhaseOne(): Boolean = board.size * board.size > board.pawns

    fun changeColor() {
        currentColor = if (currentColor == Constants.WHITE) Constants.BLACK else Constants.WHITE
    }
}