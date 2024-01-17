package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Utils.Companion.retry

class SeegaGame(
    private val inputReader: InputReader,
    private val outputPrinter: OutputPrinter,
) {

    fun run() {
        outputPrinter.printWelcomeMessage()

        outputPrinter.printBoardSizePrompt()
        val board = chooseBoardPhase()
        val seegaController = SeegaController(board)

        outputPrinter.printPhaseOnePrompt()
        gamePhaseOne(seegaController, board)

        seegaController.proceedToNextPhase()
        outputPrinter.printBoard(board)

        outputPrinter.printPhaseTwoPrompt()
        gamePhaseTwo(seegaController, board)

        outputPrinter.printGameFinishedMessage()
    }

    private fun chooseBoardPhase(): Board = retry { Board(inputReader.readBoardSize()) }.also { outputPrinter.printBoard(it) }

    private fun gamePhaseOne(seegaController: SeegaController, board: Board) {
        while (seegaController.isPhaseOne()) {
            repeat(2) {
                retry {
                    outputPrinter.printPlayerTurn(seegaController.currentPlayerColor)
                    val (col, row) = inputReader.readDeployCommand()
                    seegaController.executeDeploy(col, row).also { outputPrinter.printBoard(board) }
                }
            }
            seegaController.changeColor()
        }
    }

    private fun gamePhaseTwo(seegaController: SeegaController, board: Board) {
        while (seegaController.isPhaseTwo()) {
            val shouldChangeColor = retry {
                outputPrinter.printPlayerTurn(seegaController.currentPlayerColor)
                val (col, row, direction) = inputReader.readMoveCommand()
                seegaController.executeMove(col, row, direction).also { outputPrinter.printBoard(board) }
            }
            if (shouldChangeColor) seegaController.changeColor()
        }
    }
}