package pl.edu.mimuw

import pl.edu.mimuw.seega.io.InputReader
import pl.edu.mimuw.seega.io.OutputPrinter
import pl.edu.mimuw.seega.SeegaGame

fun main() {
    val inputReader = InputReader()
    val outputPrinter = OutputPrinter()

    val game = SeegaGame(inputReader, outputPrinter)
    game.run()
}
