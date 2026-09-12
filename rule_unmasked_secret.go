package actionlint

import (
	"regexp"
	"strings"
)

// secretsRefRE matches ${{ secrets.VARNAME }} expressions inside a run script.
// Captures the secret name in group 1.
var secretsRefRE = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// echoLineRE matches a shell line whose first command token is "echo" (preceded by optional
// whitespace, pipes, semicolons, &&, or || operators) and captures the rest of the line.
var echoLineRE = regexp.MustCompile(`(?:^|[|;&]|\|\|)\s*echo\s+(.*)`)

// addMaskRE matches the GitHub Actions add-mask workflow command in any form commonly used:
//
//	echo "::add-mask::VALUE"
//	echo '::add-mask::VALUE'
var addMaskRE = regexp.MustCompile(`::add-mask::`)

// sensitiveEnvVarRE matches environment variable names that are conventionally used to store
// credentials.  The match is case-insensitive.
var sensitiveEnvVarRE = regexp.MustCompile(`(?i)(PASSWORD|TOKEN|SECRET|API_KEY|KEY)`)

// echoEnvVarRE matches an echo command that directly expands a shell env var ($NAME or ${NAME}).
// Captures the variable name in group 1.
var echoEnvVarRE = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// RuleUnmaskedSecret detects GitHub Actions run steps that echo secret values to the log
// without first masking them with the ::add-mask:: workflow command.  Exposing secrets in
// workflow logs leaks them to anyone who can read the run output.
//
// The rule raises an error for:
//  1. Any run step that echoes a ${{ secrets.NAME }} expression when no prior step in the
//     same job issued ::add-mask:: for that secret.
//  2. Any run step that echoes an environment variable whose name matches a credential
//     pattern (PASSWORD, TOKEN, SECRET, KEY, API_KEY).
type RuleUnmaskedSecret struct {
	RuleBase
	// maskedSecrets tracks which ${{ secrets.NAME }} values have been masked (via ::add-mask::)
	// in the current job, keyed by the secret name in upper-case.
	maskedSecrets map[string]bool
	// hasMaskCommand is true when the current job contains at least one ::add-mask:: command
	// anywhere in its steps processed so far, used as a fast short-circuit.
	hasMaskCommand bool
}

// NewRuleUnmaskedSecret creates a new RuleUnmaskedSecret instance.
func NewRuleUnmaskedSecret() *RuleUnmaskedSecret {
	return &RuleUnmaskedSecret{
		RuleBase: NewRuleBase(
			"unmasked-secret",
			"Checks for run steps that echo secrets or credential environment variables without masking them with ::add-mask::, which would expose the values in the workflow log",
		),
		maskedSecrets: make(map[string]bool),
	}
}

// VisitJobPre resets per-job state before descending into the job's steps.
func (r *RuleUnmaskedSecret) VisitJobPre(n *Job) error {
	r.maskedSecrets = make(map[string]bool)
	r.hasMaskCommand = false
	return nil
}

// VisitStep inspects each run step for unmasked secret echoing.
func (r *RuleUnmaskedSecret) VisitStep(n *Step) error {
	run, ok := n.Exec.(*ExecRun)
	if !ok || run.Run == nil {
		return nil
	}

	script := run.Run.Value
	pos := run.Run.Pos

	// First pass: record any ::add-mask:: invocations in this step so they protect later
	// secrets referenced within the same step or subsequent steps.
	if addMaskRE.MatchString(script) {
		r.hasMaskCommand = true
		// Record which secrets are being masked by examining ::add-mask::${{ secrets.NAME }}.
		for _, m := range secretsRefRE.FindAllStringSubmatch(script, -1) {
			// m[1] is the secret name; check it appears near the add-mask command.
			secretName := strings.ToUpper(m[1])
			r.maskedSecrets[secretName] = true
		}
	}

	// Second pass: look for echo of secrets context references.
	r.checkEchoSecrets(script, pos)

	// Third pass: look for echo of sensitive environment variables defined on this job step.
	r.checkEchoEnvVars(script, n.Env, pos)

	return nil
}

// checkEchoSecrets detects lines that echo a ${{ secrets.NAME }} expression without a prior
// add-mask for that secret.
func (r *RuleUnmaskedSecret) checkEchoSecrets(script string, pos *Pos) {
	for _, line := range strings.Split(script, "\n") {
		echoMatches := echoLineRE.FindAllStringSubmatch(line, -1)
		if len(echoMatches) == 0 {
			continue
		}
		// Check whether the argument portion of the echo contains a secrets reference.
		for _, em := range echoMatches {
			arg := em[1]
			for _, sm := range secretsRefRE.FindAllStringSubmatch(arg, -1) {
				secretName := strings.ToUpper(sm[1])
				if !r.maskedSecrets[secretName] {
					r.Errorf(pos,
						"secret ${{ secrets.%s }} is echoed to the log without a prior ::add-mask:: command; "+
							"this leaks the secret value in the workflow run log",
						sm[1],
					)
				}
			}
		}
	}
}

// checkEchoEnvVars detects lines that echo an environment variable whose name matches a
// credential naming pattern (PASSWORD, TOKEN, SECRET, KEY, API_KEY).
func (r *RuleUnmaskedSecret) checkEchoEnvVars(script string, env *Env, pos *Pos) {
	if env == nil {
		return
	}

	// Collect the names of sensitive env vars defined on this step.
	sensitive := make(map[string]bool)
	for name := range env.Vars {
		if sensitiveEnvVarRE.MatchString(name) {
			sensitive[strings.ToUpper(name)] = true
		}
	}
	if len(sensitive) == 0 {
		return
	}

	for _, line := range strings.Split(script, "\n") {
		if !echoLineRE.MatchString(line) {
			continue
		}
		for _, vm := range echoEnvVarRE.FindAllStringSubmatch(line, -1) {
			varName := strings.ToUpper(vm[1])
			if sensitive[varName] {
				r.Errorf(pos,
					"environment variable %s matches a credential naming pattern and is echoed directly in a run step; "+
						"use ::add-mask:: before echoing credential values",
					vm[1],
				)
			}
		}
	}
}
