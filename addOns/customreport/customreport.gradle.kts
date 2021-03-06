version = "6"
description = "New HTML report module allows users to customize report content."

zapAddOn {
    addOnName.set("CustomReport")
    zapVersion.set("2.5.0")

    manifest {
        author.set("Chienli Ma")
    }
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "**/ReportGenerator.java",
        "**/ReportLastScan.java"))
}
