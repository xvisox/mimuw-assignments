package pl.edu.mimuw.seega

class Constants {
    companion object {
        val FIRST_ROW_INDENT = " ".repeat(5)
        val FIRST_ROW_SPACING = " ".repeat(3)
        val ROW_INDENT = " ".repeat(3)

        const val BLACK = 'B'
        const val WHITE = 'W'
        const val EMPTY = ' '
        const val STAR = '*'

        const val DEPLOY = "deploy"
        const val MOVE = "move"
        val DEPLOY_PATTERN = Regex("$DEPLOY [a-z][1-9]")
        val MOVE_PATTERN = Regex("$MOVE [a-z][1-9] [a-z]{2,5}")

        const val SMALL_BOARD_SIZE = 5
        const val MEDIUM_BOARD_SIZE = 7
        const val LARGE_BOARD_SIZE = 9
    }
}