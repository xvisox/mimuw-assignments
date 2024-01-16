package pl.edu.mimuw.seega

class Utils {
    companion object {
        fun <T> retry(retries: Int = 5, block: () -> T): T {
            var attempt = 0

            while (attempt < retries) {
                try {
                    return block()
                } catch (e: Exception) {
                    attempt++
                    println(e.message)
                }
            }

            throw Exception("All attempts failed.")
        }
    }
}