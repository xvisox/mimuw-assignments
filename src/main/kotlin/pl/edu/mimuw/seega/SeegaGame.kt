package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.utils.GeneralUtils.Companion.retry
import pl.edu.mimuw.seega.domain.Board
import pl.edu.mimuw.seega.io.InputReader
import pl.edu.mimuw.seega.io.OutputPrinter

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

        outputPrinter.printWonMessage(seegaController.whoWon())
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
            seegaController.endPlayerTurn()
        }
    }

    private fun gamePhaseTwo(seegaController: SeegaController, board: Board) {
        while (seegaController.isPhaseTwo()) {
            if (!seegaController.validMoveExistsForCurrentPlayer()) {
                seegaController.endPlayerTurn()
                continue
            }
            val pawnsTaken = retry {
                outputPrinter.printPlayerTurn(seegaController.currentPlayerColor)
                val (col, row, direction) = inputReader.readMoveCommand()
                seegaController.executeMove(col, row, direction).also { outputPrinter.printBoard(board) }
            }
            if (!pawnsTaken) seegaController.endPlayerTurn()
        }
    }
}