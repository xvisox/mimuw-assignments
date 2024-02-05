package pl.edu.mimuw

import pl.edu.mimuw.dsl.smd.buildSMD

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Provide <output-file-path> as a command line argument.")
        return
    }

    val smd = buildSMD {
        h1 {
            +"Lorem ipsum"
        }

        h2 {
            +"dolor sit amet"
        }

        p {
            +"Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
            br {}
            +"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        }

        p {
            +"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
        }

        item { +"Duis aute irure" }
        item { +"dolor in reprehenderit" }

        nl {}

        item(1) { +"in voluptate velit esse" }
        item(2) { +"cillum dolore eu fugiat nulla pariatur." }

        nl {}
        hr {}
        nl {}

        p {
            +"Excepteur "
            italic {
                +"sint"
            }
            +" occaecat "
            bold {
                +"cupidatat"
            }
            +" non "
            bold {
                italic {
                    +"proident"
                }
            }
            +", "
            code {
                +"sunt in culpa"
            }
        }

        codeBlock {
            +"qui officia deserunt"
            nl {}
            +"mollit anim id est laborum."
        }
    }
    val filePath = args[0]
    smd.writeToFile(filePath)
}
