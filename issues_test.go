package hstspreload

import "testing"

const (
	issuesShouldMatch = `Issues should match expected.
## Actual

%#v

## Expected

%#v

`
	issuesShouldBeEmpty = `Issues should be empty.
## Actual

%#v

`
)

var issuesMatchExpectedTests = []struct {
	actual   Issues
	expected Issues
}{
	{Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}, Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}},
	{Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}, Issues{}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error"),
		Issues{
			Errors: []Issue{{
				Code:    "error1",
				Summary: "Summary 1",
				Message: "Single Error",
			}},
		}},
	{Issues{}.addErrorf("error1", "", ""),
		Issues{
			Errors: []Issue{{
				Code: "error1",
			}},
		}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error"),
		Issues{
			Errors: []Issue{{
				Code:    "error1",
				Summary: "Summary 1",
			}},
		}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error"),
		Issues{
			Errors: []Issue{{
				Code: "error1",
			}},
		}},
	{Issues{}.addErrorf("error1", "", "Single Error").addErrorf("error2", "", "Second Error"),
		Issues{
			Errors: []Issue{
				{Code: "error1"},
				{Code: "error2", Message: "Second Error"},
			},
		}},
	{Issues{}.addWarningf("warning1", "Summary 1", "Single warning"),
		Issues{
			Warnings: []Issue{{
				Code: "warning1",
			}},
		}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error").addWarningf("warning1", "Summary 1", "Single warning"),
		Issues{
			Errors: []Issue{{
				Code: "error1",
			}},
			Warnings: []Issue{{
				Code: "warning1",
			}},
		}},
}

func TestIssuesMatchExpected(t *testing.T) {
	for _, tt := range issuesMatchExpectedTests {
		if !tt.actual.Match(tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

var issuesNotEqualTests = []struct {
	actual   Issues
	expected Issues
}{
	{
		Issues{Errors: []Issue{{Code: "test1"}}},
		Issues{Warnings: []Issue{{Code: "test1"}}},
	},
	{
		Issues{Errors: []Issue{{Code: "test1"}, {Code: "test2"}}},
		Issues{Errors: []Issue{{Code: "test1"}}},
	},
	{
		Issues{Errors: []Issue{{Code: "pie"}, {Code: "cake"}, {Code: "anything you bake"}}},
		Issues{Errors: []Issue{{Code: "cake"}, {Code: "pie"}, {Code: "anything you bake"}}},
	},
}

func TestIssuesNotEqual(t *testing.T) {
	for _, tt := range issuesNotEqualTests {
		if tt.actual.Match(tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

func TestAddUniqueErrorf(t *testing.T) {
	iss := Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
		},
	}

	var expected Issues

	iss = iss.addUniqueErrorf("error2", "", "")
	expected = Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
		},
	}
	if !iss.Match(expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueErrorf("error3", "", "")
	expected = Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
			{Code: "error3"},
		},
	}
	if !iss.Match(expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueErrorf("error1", "", "")
	expected = Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
			{Code: "error3"},
		},
	}
	if !iss.Match(expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}
}

func TestAddUniqueWarningf(t *testing.T) {
	iss := Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
		},
	}

	var expected Issues

	iss = iss.addUniqueWarningf("warning2", "", "")
	expected = Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
		},
	}
	if !iss.Match(expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueWarningf("warning3", "", "")
	expected = Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
			{Code: "warning3"},
		},
	}
	if !iss.Match(expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueWarningf("warning1", "", "")
	expected = Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
			{Code: "warning3"},
		},
	}
	if !iss.Match(expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}
}
