package hstspreload

import (
	"encoding/json"
	"fmt"
)

// An IssueCode is a string identifier for an Issue.
// This allows other programs to perform analysis or take actions
// based on specific issues.
//
// Examples: "domain.is_subdomain", "domain.tls.cannot_connect", "header.preloadable.max_age.below_1_year"
type IssueCode string

// An Issue is an error or a warning relating to a site's HSTS preload
// configuration.
type Issue struct {
	// An error code.
	Code IssueCode `json:"code"`
	// A short summary (≈2-5 words) of the issue.
	Summary string `json:"summary"`
	// A detailed explanation with instructions for fixing.
	Message string `json:"message"`
}

// The Issues struct encapsulates a set of errors and warnings.
// By convention:
//
// - Errors contains a list of errors that will prevent preloading.
//
// - Warnings contains a list errors that are a good idea to fix,
// but are okay for preloading.
//
// - Warning and errors will state at which level the issue occurred (e.g. header syntax, preload requirement checking, HTTP response checking, domain checking).
//
// - If Issues is returned from a Check____() function without any errors
// or warnings, it means that the function passed all checks.
//
// - The list of errors is not guaranteed to be exhaustive. In
// particular, fixing a given error (e.g. "could not connect to
// server") may bring another error to light (e.g. "HSTS header was
// not found").
type Issues struct {
	Errors   []Issue `json:"errors"`
	Warnings []Issue `json:"warnings"`
}

func (iss Issues) addErrorf(code IssueCode, summary string, format string, args ...interface{}) Issues {
	formattedError := fmt.Sprintf(format, args...)
	return Issues{
		Errors:   append(iss.Errors, Issue{code, summary, formattedError}),
		Warnings: iss.Warnings,
	}
}

func (iss Issues) addWarningf(code IssueCode, summary string, format string, args ...interface{}) Issues {
	formattedWarning := fmt.Sprintf(format, args...)
	return Issues{
		Errors:   iss.Errors,
		Warnings: append(iss.Warnings, Issue{code, summary, formattedWarning}),
	}
}

func (iss Issues) addUniqueErrorf(code IssueCode, summary string, format string, args ...interface{}) Issues {
	for _, err := range iss.Errors {
		if err.Code == code {
			return iss
		}
	}
	return iss.addErrorf(code, summary, format, args...)
}

func (iss Issues) addUniqueWarningf(code IssueCode, summary string, format string, args ...interface{}) Issues {
	for _, warning := range iss.Warnings {
		if warning.Code == code {
			return iss
		}
	}
	return iss.addWarningf(code, summary, format, args...)
}

func combineIssues(issues1 Issues, issues2 Issues) Issues {
	return Issues{
		Errors:   append(issues1.Errors, issues2.Errors...),
		Warnings: append(issues1.Warnings, issues2.Warnings...),
	}
}

// Match checks that the given issues match the `wanted` ones. This
// function always checks that both the lists of Errors and Warnings
// have the same number of `Issue`s with the same `IssuesCode`s codes in
// the same order. If any issues in `wanted` have the Summary or Message
// field set, the field is also compared against the field from the
// corresponding issue in `iss`.
func (iss Issues) Match(wanted Issues) bool {
	if len(iss.Errors) != len(wanted.Errors) {
		return false
	}

	if len(iss.Warnings) != len(wanted.Warnings) {
		return false
	}

	for e := range iss.Errors {
		if iss.Errors[e].Code != wanted.Errors[e].Code {
			return false
		}
		if wanted.Errors[e].Summary != "" && iss.Errors[e].Summary != wanted.Errors[e].Summary {
			return false
		}
		if wanted.Errors[e].Message != "" && iss.Errors[e].Message != wanted.Errors[e].Message {
			return false
		}
	}

	for w := range iss.Warnings {
		if iss.Warnings[w].Code != wanted.Warnings[w].Code {
			return false
		}
		if wanted.Warnings[w].Summary != "" && iss.Warnings[w].Summary != wanted.Warnings[w].Summary {
			return false
		}
		if wanted.Warnings[w].Message != "" && iss.Warnings[w].Message != wanted.Warnings[w].Message {
			return false
		}
	}

	return true
}

func formatIssueListForString(list []Issue) string {
	output := ""
	if len(list) > 1 {
		for _, l := range list {
			output += fmt.Sprintf("\n		%#v,", l)
		}
		output += "\n	"
	} else if len(list) == 1 {
		output = fmt.Sprintf(`%#v`, list[0])
	}

	return output
}

// GoString formats `iss` with multiple lines and indentation.
// This is mainly used to provide output for unit tests in this project
// that can be pasted back into the relevant unit tess.
func (iss Issues) GoString() string {
	return fmt.Sprintf(`Issues{
	Errors:   []string{%s},
	Warnings: []string{%s},
}`,
		formatIssueListForString(iss.Errors),
		formatIssueListForString(iss.Warnings),
	)
}

// MarshalJSON converts the given Issues to JSON, making sure that
// empty Errors/Warnings are converted to empty lists rather than null.
func (iss Issues) MarshalJSON() ([]byte, error) {
	// We explicitly fill out the fields with slices so that they are
	// marshalled to `[]` rather than `null` when they are empty.
	if len(iss.Errors) == 0 {
		iss.Errors = make([]Issue, 0)
	}
	if len(iss.Warnings) == 0 {
		iss.Warnings = make([]Issue, 0)
	}

	// We use a type alias to call the "default" implementation of
	// json.Marshal on Issues.
	// See http://choly.ca/post/go-json-marshalling/
	type issuesData Issues
	return json.Marshal(issuesData(iss))
}
