import pl.edu.mimuw.Dependencies
import org.gradle.kotlin.dsl.run as runApplication

plugins {
    kotlin("jvm") version "1.9.10"
    application
    java
}

group = "pl.edu.mimuw"
version = "1.0-SNAPSHOT"

application {
    mainClass.set("pl.edu.mimuw.MainKt")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.set(listOf("-Xcontext-receivers"))
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

tasks.runApplication {
    standardInput = System.`in`
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(Dependencies.Kotest.runner)
    testImplementation(Dependencies.Kotest.assertions)
    testImplementation(Dependencies.Kotest.property)
}

tasks.test {
    useJUnitPlatform()
}
