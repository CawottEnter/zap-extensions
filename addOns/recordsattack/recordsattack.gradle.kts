import org.zaproxy.gradle.addon.AddOnStatus

version = "1.1.0"
description = "Record scenario and replay with change parameter"

zapAddOn {
    addOnName.set("Record Attack")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("Pierre Ribault")
        url.set("https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsSpiderAjaxConcepts")
        dependencies {
            addOns {
                register("selenium") {
                    version.set("15.*")
                }
                register("ascanrules") {
                    version.set("34.*")
                }
            }
        }
    }

    val apiGenClasspath = configurations.detachedConfiguration(
        dependencies.create("org.zaproxy:zap:2.8.0"),
        dependencies.create(parent!!.childProjects.get("selenium")!!),
        dependencies.create(parent!!.childProjects.get("ascanrules")!!)
    )

    apiClientGen {
        api.set("org.zaproxy.zap.extension.recordsattack.AjaxSpiderAPI")
        options.set("org.zaproxy.zap.extension.recordsattack.AjaxSpiderParam")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/recordsattack/resources/Messages.properties"))
        classpath.run {
            setFrom(apiGenClasspath)
            from(tasks.named(JavaPlugin.JAR_TASK_NAME))
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("selenium")!!)
    compileOnly(parent!!.childProjects.get("ascanrules")!!)
    implementation("net.lightbody.bmp:browsermob-core:2.1.5")
    implementation("net.lightbody.bmp:browsermob-proxy:2.1.5")
    implementation(files("lib/crawljax-core-3.7.jar"))
    implementation("commons-math:commons-math:1.2")
    implementation("net.lightbody.bmp:browsermob-core:2.1.5")
    implementation("net.lightbody.bmp:browsermob-proxy:2.1.5")
    implementation("com.codahale.metrics:metrics-core:3.0.2")
    implementation("com.google.code.findbugs:jsr305:3.0.0")
    implementation("com.google.inject.extensions:guice-assistedinject:3.0") {
        // Not needed.
        exclude(group = "org.sonatype.sisu.inject", module = "cglib")
    }
    implementation("net.jcip:jcip-annotations:1.0")
    implementation("net.sourceforge.nekohtml:nekohtml:1.9.21") {
        // Not needed.
        exclude(group = "xerces", module = "xercesImpl")
    }
    implementation("org.slf4j:jcl-over-slf4j:1.7.6")
    implementation("org.slf4j:jul-to-slf4j:1.7.6")
    implementation("org.slf4j:slf4j-log4j12:1.7.6") {
        // Provided by ZAP.
        exclude(group = "log4j", module = "log4j")
    }
    implementation("com.fasterxml.jackson.core:jackson-core:2.9.6")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.9.6")
    implementation("org.apache.commons:commons-lang3:3.5")
    implementation("com.fasterxml.jackson.core:jackson-annotations:2.9.6")
    implementation("xmlunit:xmlunit:1.5")
}