package attack

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	ID          string
	Title       string
	Severity    Severity
	Method      string
	Path        string
	StatusCode  int
	Evidence    string
	Remediation string
}
