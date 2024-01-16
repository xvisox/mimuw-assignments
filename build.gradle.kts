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
    testImplementation("org.junit.jupiter:junit-jupiter:5.7.1")
    testImplementation ("com.github.stefanbirkner:system-lambda:1.2.0")
}

tasks.test {
    useJUnitPlatform()
}
