package pl.edu.mimuw

object Dependencies {
    object Kotest {
        private val version = "5.7.2"
        private fun kotest(module: String): String =
            "io.kotest:kotest-$module:$version"
        val runner = kotest("runner-junit5")
        val assertions = kotest("assertions-core")
        val property = kotest("property")
    }
}
