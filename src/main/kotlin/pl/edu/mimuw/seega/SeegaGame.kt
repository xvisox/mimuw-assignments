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

        outputPrinter.printPhaseTwoPrompt()
        gamePhaseTwo(seegaController, board)

        outputPrinter.printGameFinishedMessage()
    }

    private fun chooseBoardPhase(): Board = retry { Board(inputReader.readBoardSize()) }

    private fun gamePhaseOne(seegaController: SeegaController, board: Board) {
        while (seegaController.isPhaseOne()) {
            repeat(2) {
                retry {
                    outputPrinter.printPlayerTurn(seegaController.currentColor)
                    val (col, row) = inputReader.readDeployCommand()
                    seegaController.executeDeploy(col, row)
                    outputPrinter.printBoard(board)
                }
            }
            seegaController.changeColor()
        }
    }

    private fun gamePhaseTwo(seegaController: SeegaController, board: Board) {

    }
}