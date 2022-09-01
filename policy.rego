package trivy

import data.lib.trivy

default ignore = false

ignore_severities := {"LOW", "MEDIUM"}

ignore_cves := {
}

ignore {
	input.VulnerabilityID == ignore_cves[_]
}

ignore {
	input.Severity == ignore_severities[_]
}
