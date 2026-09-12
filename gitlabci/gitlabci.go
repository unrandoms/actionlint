// Package gitlabci implements a security linter for GitLab CI pipeline configuration files.
// It detects script injection vulnerabilities arising from unquoted expansion of user-controlled
// CI variables such as CI_COMMIT_MESSAGE and CI_MERGE_REQUEST_TITLE.
package gitlabci

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v4"
)

// Diagnostic represents a single linting finding produced by the GitLab CI linter.
// Its fields mirror actionlint.Error so callers can convert between them without reflection.
type Diagnostic struct {
	// Message is the human-readable description of the finding.
	Message string
	// Filepath is the path to the file where the finding was detected.
	Filepath string
	// Line is the 1-based source line number.
	Line int
	// Column is the 1-based source column number.
	Column int
	// Kind is the rule identifier that produced this finding.
	Kind string
}

// Error returns a single-line representation of the diagnostic, matching the actionlint.Error format.
func (d *Diagnostic) Error() string {
	return fmt.Sprintf("%s:%d:%d: %s [%s]", d.Filepath, d.Line, d.Column, d.Message, d.Kind)
}

// userControlledVars lists CI variables whose values originate from user-supplied data
// (commit messages, MR titles, descriptions) and must never be expanded unquoted in shell.
var userControlledVars = []string{
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_TITLE",
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
}

// unquotedVarRE matches bare $VARNAME and ${VARNAME} forms for each user-controlled variable.
var unquotedVarRE = buildUnquotedVarRE()

func buildUnquotedVarRE() *regexp.Regexp {
	alts := make([]string, 0, len(userControlledVars)*2)
	for _, v := range userControlledVars {
		// $VARNAME with word boundary
		alts = append(alts, `\$`+regexp.QuoteMeta(v)+`\b`)
		// ${VARNAME}
		alts = append(alts, `\$\{`+regexp.QuoteMeta(v)+`\}`)
	}
	return regexp.MustCompile(strings.Join(alts, "|"))
}

// isInSingleQuotes reports whether the byte at index pos in line is contained within a
// single-quoted shell string. In POSIX sh, single quotes are non-nestable and nothing inside
// them can be escaped, so a simple toggle scan is sufficient.
func isInSingleQuotes(line string, pos int) bool {
	inside := false
	for i := 0; i < pos && i < len(line); i++ {
		if line[i] == '\'' {
			inside = !inside
		}
	}
	return inside
}

// checkScriptLine scans one shell script line for unquoted expansions of user-controlled
// CI variables and returns diagnostics for each occurrence found outside single quotes.
func checkScriptLine(text, path string, lineNum int) []*Diagnostic {
	matches := unquotedVarRE.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	var diags []*Diagnostic
	for _, loc := range matches {
		if isInSingleQuotes(text, loc[0]) {
			continue // safely inside single quotes
		}
		raw := text[loc[0]:loc[1]]
		// Derive a clean variable name for the message (strip $, {, }).
		varName := strings.TrimPrefix(raw, "$")
		varName = strings.TrimPrefix(varName, "{")
		varName = strings.TrimSuffix(varName, "}")

		diags = append(diags, &Diagnostic{
			Message: fmt.Sprintf(
				"user-controlled CI variable $%s is expanded without single-quote protection; "+
					"this allows script injection via attacker-controlled commit or MR metadata",
				varName,
			),
			Filepath: path,
			Line:     lineNum,
			Column:   loc[0] + 1,
			Kind:     "gitlab-script-injection",
		})
	}
	return diags
}

// scriptLine pairs a resolved shell command string with its 1-based YAML source line number.
type scriptLine struct {
	text string
	line int
}

// reservedTopLevelKeys contains .gitlab-ci.yml keys that are configuration directives, not jobs.
var reservedTopLevelKeys = map[string]bool{
	"stages":        true,
	"variables":     true,
	"include":       true,
	"image":         true,
	"services":      true,
	"before_script": true,
	"after_script":  true,
	"cache":         true,
	"default":       true,
	"workflow":      true,
}

// scriptFieldNames are the job-level keys that contain shell commands to execute.
var scriptFieldNames = map[string]bool{
	"script":        true,
	"before_script": true,
	"after_script":  true,
}

// extractJobScriptLines walks a YAML MappingNode that represents a single job definition
// and returns every shell script line together with its source line number.
func extractJobScriptLines(jobNode *yaml.Node) []scriptLine {
	var lines []scriptLine
	if jobNode == nil || jobNode.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i+1 < len(jobNode.Content); i += 2 {
		keyNode := jobNode.Content[i]
		valNode := jobNode.Content[i+1]

		if !scriptFieldNames[keyNode.Value] {
			continue
		}

		switch valNode.Kind {
		case yaml.SequenceNode:
			for _, item := range valNode.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				// Multi-line scalar values (block scalars) contain embedded newlines.
				for j, l := range strings.Split(item.Value, "\n") {
					lines = append(lines, scriptLine{text: l, line: item.Line + j})
				}
			}
		case yaml.ScalarNode:
			for j, l := range strings.Split(valNode.Value, "\n") {
				lines = append(lines, scriptLine{text: l, line: valNode.Line + j})
			}
		}
	}
	return lines
}

// Lint parses the GitLab CI YAML file at path, applies all security checks, and returns
// a slice of diagnostics for every finding detected.  An error is returned only when the
// file cannot be read or is not valid YAML.
func Lint(path string) ([]*Diagnostic, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gitlabci: could not read %q: %w", path, err)
	}

	// Unmarshal into a yaml.Node tree to retain precise source positions.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("gitlabci: could not parse YAML in %q: %w", path, err)
	}

	// yaml.Unmarshal into a yaml.Node produces a DocumentNode whose sole child is the
	// top-level MappingNode.
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil
	}
	topMapping := root.Content[0]
	if topMapping.Kind != yaml.MappingNode {
		return nil, nil
	}

	var diags []*Diagnostic

	// Walk top-level key/value pairs; keys at odd indices in Content are yaml.ScalarNodes
	// whose Value is the key string.
	for i := 0; i+1 < len(topMapping.Content); i += 2 {
		keyNode := topMapping.Content[i]
		valNode := topMapping.Content[i+1]

		if reservedTopLevelKeys[keyNode.Value] {
			continue
		}
		// Job definitions are mappings; skip scalars and sequences at top level.
		if valNode.Kind != yaml.MappingNode {
			continue
		}

		for _, sl := range extractJobScriptLines(valNode) {
			diags = append(diags, checkScriptLine(sl.text, path, sl.line)...)
		}
	}

	return diags, nil
}
