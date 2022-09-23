package trivy

import data.lib.trivy

default ignore = false

ignore_severities := {"LOW", "MEDIUM"}

ignore_cves := {
      "CVE-2022-37434",
      "CVE-2021-3999",
      "CVE-2022-40674"
}

ignore {
	input.VulnerabilityID == ignore_cves[_]
}

ignore {
	input.Severity == ignore_severities[_]
}
