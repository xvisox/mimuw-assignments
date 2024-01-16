package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Utils.Companion.retry

class SeegaController(
    private val inputReader: InputReader,
) {
    private var currentColor: Char = Constants.WHITE

    fun createBoard(): Board = Board(retry { inputReader.readBoardSize() })

    fun executeDeploy(board: Board) {
        retry {
            inputReader.readDeployCommand().let {
                if (!board.isFieldEmpty(it.first, it.second)) throw Exception("Field is not empty."); it
            }
        }.also { (col, row) ->
            board.placePawn(col, row, currentColor)
        }
    }

    fun executeMove(board: Board): Unit = TODO()

    fun isPhaseOne(board: Board): Boolean = !board.isFull()

    fun changeColor() {
        currentColor = if (currentColor == Constants.WHITE) Constants.BLACK else Constants.WHITE
    }
}