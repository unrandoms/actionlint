package actionlint

import (
	"encoding/json"
	"io"
)

// sarifSchema is the canonical URI for the SARIF 2.1.0 JSON schema.
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// sarifDocument is the root object of a SARIF 2.1.0 log file.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// sarifLevelForKind maps rule kind strings to their SARIF level. Rules that only report
// informational findings can be mapped to "note"; most security rules are "error".
func sarifLevelForKind(kind string) string {
	switch kind {
	case "permissions", "glob":
		return "warning"
	default:
		return "error"
	}
}

// WriteSARIF serialises errors as a SARIF 2.1.0 document and writes it to w.
// The toolVersion parameter is used to populate the driver version field; pass the
// result of getCommandVersion().
func WriteSARIF(w io.Writer, errs []*Error, toolVersion string) error {
	results := make([]sarifResult, 0, len(errs))
	for _, e := range errs {
		col := e.Column
		if col < 1 {
			col = 1
		}
		line := e.Line
		if line < 1 {
			line = 1
		}

		results = append(results, sarifResult{
			RuleID: e.Kind,
			Level:  sarifLevelForKind(e.Kind),
			Message: sarifMessage{
				Text: e.Message,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: e.Filepath,
						},
						Region: sarifRegion{
							StartLine:   line,
							StartColumn: col,
						},
					},
				},
			},
		})
	}

	doc := sarifDocument{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "pipelinesec",
						Version: toolVersion,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return nil
}
