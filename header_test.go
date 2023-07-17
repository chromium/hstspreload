package hstspreload

import (
	"fmt"
	"testing"

	"github.com/chromium/hstspreload/chromium/preloadlist"
)

const (
	headersShouldBeEqual = `Header did not match expected value after parsing.
			Actual: %v
			Expected: %v`
)

func ExampleParseHeaderString() {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age;")
	fmt.Printf("%v\n%v", hstsHeader, issues)
}

/******** HSTSHeader Comparison *********/

func headersEqual(header1 HSTSHeader, header2 HSTSHeader) bool {
	if header1.Preload != header2.Preload {
		return false
	}

	if header1.IncludeSubDomains != header2.IncludeSubDomains {
		return false
	}

	if (header1.MaxAge == nil) != (header2.MaxAge == nil) {
		return false
	}
	if header1.MaxAge != nil && header2.MaxAge != nil && header1.MaxAge.Seconds != header2.MaxAge.Seconds {
		return false
	}

	return true
}

func TestHeadersEqual(t *testing.T) {
	if !headersEqual(
		HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            &MaxAge{Seconds: 12345},
		},
		HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            &MaxAge{Seconds: 12345},
		},
	) {
		t.Errorf("HSTSHeader structs should be considered equal if all values match.")
	}

	if headersEqual(
		HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            &MaxAge{Seconds: 12345},
		},
		HSTSHeader{
			Preload:           true,
			IncludeSubDomains: true,
			MaxAge:            &MaxAge{Seconds: 12345},
		},
	) {
		t.Errorf("HSTSHeader structs should be considered non-equal if preload values don't match.")
	}
}

var parseHeaderStringTests = []struct {
	description        string
	header             string
	expectedIssues     Issues
	expectedHSTSHeader HSTSHeader
}{

	/******** no warnings, no errors ********/

	{
		"without preload",
		"includeSubDomains; max-age=1337",
		Issues{},
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 1337}},
	},
	{
		"without includeSubDomains",
		"preload; max-age=1337",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: false, MaxAge: &MaxAge{Seconds: 1337}},
	},
	{
		"without max-age",
		"preload; includeSubDomains",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: nil},
	},
	{
		"full",
		"max-age=31536000; includeSubDomains; preload",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 31536000}},
	},
	{
		"any order",
		"includeSubDomains; preload; max-age=4321",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 4321}},
	},
	{
		"extra whitespace",
		"   max-age=10886400  ;     includeSubDomains    ;     preload      ",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 10886400}},
	},
	{
		"larger max-age",
		"includeSubDomains; preload; max-age=12345678",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 12345678}},
	},
	{
		"reordered",
		"max-age=10886400; preload; includeSubDomains",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 10886400}},
	},
	{
		"reordered, without preload",
		"max-age=10886400; includeSubDomains",
		Issues{},
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 10886400}},
	},
	{
		"case-insensitive",
		"inCLUDESUBDomaINs; max-AGe=12345678",
		Issues{},
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 12345678}},
	},

	/******** no errors, warnings only ********/

	{
		"empty",
		"",
		Issues{Warnings: []Issue{{Code: "header.parse.empty"}}},
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: nil},
	},
	{
		"repeated preload",
		"preload; includeSubDomains; preload; max-age=12345678; preload",
		Issues{Warnings: []Issue{{Code: "header.parse.repeated.preload"}}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 12345678}},
	},
	{
		"single extra directive",
		"includeSubDomains; max-age=12345678; preload; extraDirective",
		Issues{Warnings: []Issue{{Code: "header.parse.unknown_directive"}}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 12345678}},
	},
	{
		"multiple extra directives",
		"max-age=12345678; extra; includeSubDomains; directives; preload",
		Issues{Warnings: []Issue{
			{Code: "header.parse.unknown_directive"},
			{Code: "header.parse.unknown_directive"},
		}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 12345678}},
	},
	{
		"semicolon only",
		";",
		Issues{Warnings: []Issue{{Code: "header.parse.empty_directive"}}},
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: nil},
	},
	{
		"trailing semicolon",
		"max-age=10886400; includeSubDomains; preload;",
		Issues{Warnings: []Issue{{Code: "header.parse.empty_directive"}}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 10886400}},
	},
	{
		"prefixed by semicolon",
		"; max-age=10886400; includeSubDomains; preload",
		Issues{Warnings: []Issue{{Code: "header.parse.empty_directive"}}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: &MaxAge{Seconds: 10886400}},
	},
	{
		"bad max-age: leading 0",
		"max-age=01234",
		Issues{Warnings: []Issue{{Code: "header.parse.max_age.leading_zero"}}},
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: &MaxAge{Seconds: 1234}},
	},
}

func TestParseHeaderString(t *testing.T) {
	for _, tt := range parseHeaderStringTests {
		hstsHeader, issues := ParseHeaderString(tt.header)
		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
		if !headersEqual(hstsHeader, tt.expectedHSTSHeader) {
			t.Errorf("[%s] "+headersShouldBeEqual, tt.description, hstsHeader, tt.expectedHSTSHeader)
		}
	}
}

var parseHeaderStringWithErrorsTests = []struct {
	description    string
	header         string
	expectedIssues Issues
}{

	/******** errors only, no warnings ********/

	{
		"bad max-age: empty value",
		"max-age=",
		Issues{Errors: []Issue{{Code: "header.parse.max_age.parse_int_error"}}},
	},
	{
		"bad max-age: no value",
		"max-age",
		Issues{Errors: []Issue{{Code: "header.parse.invalid.max_age.no_value"}}},
	},
	{
		"max-age: minus", // Motivated by https://crbug.com/596561
		"max-age=-101",   // Motivated by https://crbug.com/596561
		Issues{Errors: []Issue{{
			Code:    "header.parse.max_age.non_digit_characters",
			Message: "The header's max-age value contains characters that are not digits: `max-age=-101`",
		}}},
	},
	{
		"max-age: plus", // Motivated by https://crbug.com/596561
		"max-age=+101",
		Issues{Errors: []Issue{{
			Code:    "header.parse.max_age.non_digit_characters",
			Message: "The header's max-age value contains characters that are not digits: `max-age=+101`",
		}}},
	},

	/******** errors and warnings ********/

	{
		"error and warning: no max-age value, trailing semicolon", // Motivated by https://crbug.com/596561
		"max-age;",
		Issues{
			Errors:   []Issue{{Code: "header.parse.invalid.max_age.no_value"}},
			Warnings: []Issue{{Code: "header.parse.empty_directive"}},
		},
	},
	{
		"error and warnings: no max-age value, unknown directive, trailing semicolon", // Motivated by https://crbug.com/596561
		"includeDomains; max-age;",
		Issues{
			Errors: []Issue{{Code: "header.parse.invalid.max_age.no_value"}},
			Warnings: []Issue{
				{Code: "header.parse.unknown_directive"},
				{Code: "header.parse.empty_directive"},
			},
		},
	},
}

func TestParseHeaderStringWithErrors(t *testing.T) {
	for _, tt := range parseHeaderStringWithErrorsTests {
		_, issues := ParseHeaderString(tt.header)
		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
	}
}

/******** PreloadableHeader() ********/

// Most of the heavy testing takes place in PreloadableHeaderString().
// We include a few direct tests here as a sanity check.

func TestPreloadableHeaderMissingPreloadAndMoreThanTenYears(t *testing.T) {
	issues := PreloadableHeader(HSTSHeader{
		Preload:           false,
		IncludeSubDomains: true,
		MaxAge:            &MaxAge{Seconds: 315360001},
	})
	expected := Issues{
		Errors: []Issue{{Code: "header.preloadable.preload.missing"}},
		Warnings: []Issue{{
			Code:    "header.preloadable.max_age.over_10_years",
			Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
		}},
	}
	if !issues.Match(expected) {
		t.Errorf(issuesShouldMatch, issues, expected)
	}
}

var preloadableHeaderStringTests = []struct {
	description    string
	header         string
	expectedIssues Issues
}{

	/******** no errors, no warnings ********/

	{
		"no issues",
		"max-age=31536000; includeSubDomains; preload",
		Issues{},
	},

	/******** no errors, warnings only ********/

	{
		"max-age > 10 years",
		"max-age=315360001; preload; includeSubDomains",
		Issues{Warnings: []Issue{{
			Code:    "header.preloadable.max_age.over_10_years",
			Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
		}}},
	},

	/******** errors only, no warnings ********/

	{
		"empty",
		"",
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.include_sub_domains.missing"},
				{Code: "header.preloadable.preload.missing"},
				{Code: "header.preloadable.max_age.missing"},
			},
			Warnings: []Issue{{Code: "header.parse.empty"}},
		},
	},
	{
		"missing preload",
		"includeSubDomains; max-age=31536000",
		Issues{Errors: []Issue{{Code: "header.preloadable.preload.missing"}}},
	},
	{
		"missing includeSubdomains",
		"preload; max-age=31536000",
		Issues{Errors: []Issue{{Code: "header.preloadable.include_sub_domains.missing"}}},
	},
	{
		"missing max-age",
		"includeSubDomains; preload",
		Issues{Errors: []Issue{{Code: "header.preloadable.max_age.missing"}}},
	},
	{
		"only preload",
		"preload",
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.include_sub_domains.missing"},
				{Code: "header.preloadable.max_age.missing"},
			},
		},
	},
	{
		"only includeSubdomains",
		"includeSubDomains",
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.preload.missing"},
				{Code: "header.preloadable.max_age.missing"},
			},
		},
	},
	{
		"only max-age",
		"max-age=123456789",
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.include_sub_domains.missing"},
				{Code: "header.preloadable.preload.missing"},
			},
		},
	},
	{
		"max-age without value",
		"includeSubDomains; preload; max-age",
		Issues{
			Errors: []Issue{
				{Code: "header.parse.invalid.max_age.no_value"},
				{Code: "header.preloadable.max_age.missing"},
			},
		},
	},
	{
		"maxAge=0", // Give information about what to do if you want to remove HSTS.
		"includeSubDomains; preload; max-age=0",
		Issues{Errors: []Issue{{Code: "header.preloadable.max_age.zero"}}},
	},
	{
		"maxAge=100",
		"includeSubDomains; preload; max-age=100",
		Issues{Errors: []Issue{{
			Code:    "header.preloadable.max_age.below_1_year",
			Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=100.",
		}}},
	},
	{
		"maxAge=10886400",
		"includeSubDomains; preload; max-age=10886400",
		Issues{Errors: []Issue{{
			Code:    "header.preloadable.max_age.below_1_year",
			Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=10886400.",
		}}},
	},

	/******** errors and warnings ********/

	{
		"missing preload, >10 years",
		"max-age=315360001; includeSubDomains",
		Issues{
			Errors: []Issue{{Code: "header.preloadable.preload.missing"}},
			Warnings: []Issue{{
				Code:    "header.preloadable.max_age.over_10_years",
				Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
			}},
		},
	},
}

func TestPreloadableHeaderString(t *testing.T) {
	for _, tt := range preloadableHeaderStringTests {
		issues := PreloadableHeaderString(tt.header)
		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
	}
}

// Eligible Domain tests
var eligibleHeaderStringTests = []struct {
	description    string
	header         string
	expectedIssues Issues
	policy         preloadlist.PolicyType
}{

	/******** no errors, no warnings ********/

	{
		"no issues, policy: 1 year",
		"max-age=31536000; includeSubDomains; preload",
		Issues{},
		preloadlist.Bulk1Year,
	},
	{
		"no issues, policy: 18 weeks",
		"max-age=10886400; includeSubDomains; preload",
		Issues{},
		preloadlist.Bulk18Weeks,
	},

	/******** no errors, warnings only ********/

	{
		"max-age > 10 years, policy: 1 year",
		"max-age=315360001; preload; includeSubDomains",
		Issues{Warnings: []Issue{{
			Code:    "header.preloadable.max_age.over_10_years",
			Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
		}}},
		preloadlist.Bulk1Year,
	},
	{
		"max-age > 10 years, policy: 18 weeks",
		"max-age=315360001; preload; includeSubDomains",
		Issues{Warnings: []Issue{{
			Code:    "header.preloadable.max_age.over_10_years",
			Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
		}}},
		preloadlist.Bulk18Weeks,
	},

	/******** errors only, no warnings ********/

	{
		"empty, policy: 1 year",
		"",
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.include_sub_domains.missing"},
				{Code: "header.preloadable.preload.missing"},
				{Code: "header.preloadable.max_age.missing"},
			},
			Warnings: []Issue{{Code: "header.parse.empty"}},
		},
		preloadlist.Bulk1Year,
	},
	{
		"empty, policy: 18 weeks",
		"",
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.include_sub_domains.missing"},
				{Code: "header.preloadable.preload.missing"},
				{Code: "header.preloadable.max_age.missing"},
			},
			Warnings: []Issue{{Code: "header.parse.empty"}},
		},
		preloadlist.Bulk18Weeks,
	},
	{
		"max-age without value, policy: 1 year",
		"includeSubDomains; preload; max-age",
		Issues{
			Errors: []Issue{
				{Code: "header.parse.invalid.max_age.no_value"},
				{Code: "header.preloadable.max_age.missing"},
			},
		},
		preloadlist.Bulk1Year,
	},
	{
		"max-age without value, policy: 18 weeks",
		"includeSubDomains; preload; max-age",
		Issues{
			Errors: []Issue{
				{Code: "header.parse.invalid.max_age.no_value"},
				{Code: "header.preloadable.max_age.missing"},
			},
		},
		preloadlist.Bulk18Weeks,
	},
	{
		"maxAge=0, policy: 1 year", // Give information about what to do if you want to remove HSTS.
		"includeSubDomains; preload; max-age=0",
		Issues{Errors: []Issue{{Code: "header.preloadable.max_age.zero"}}},
		preloadlist.Bulk1Year,
	},
	{
		"maxAge=0, policy: 18 weeks", // Give information about what to do if you want to remove HSTS.
		"includeSubDomains; preload; max-age=0",
		Issues{Errors: []Issue{{Code: "header.preloadable.max_age.zero"}}},
		preloadlist.Bulk18Weeks,
	},
	{
		"maxAge=100, policy: 1 year",
		"includeSubDomains; preload; max-age=100",
		Issues{Errors: []Issue{{
			Code:    "header.preloadable.max_age.below_1_year",
			Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=100.",
		}}},
		preloadlist.Bulk1Year,
	},
	{
		"maxAge=100, policy: 18 weeks",
		"includeSubDomains; preload; max-age=100",
		Issues{Errors: []Issue{{
			Code:    "header.preloadable.max_age.below_18_weeks",
			Message: "The max-age must be at least 10886400 seconds (≈ 18 weeks), but the header currently only has max-age=100.",
		}}},
		preloadlist.Bulk18Weeks,
	},
	{
		"maxAge=10886400, policy: 1 year",
		"includeSubDomains; preload; max-age=10886400",
		Issues{Errors: []Issue{{
			Code:    "header.preloadable.max_age.below_1_year",
			Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=10886400.",
		}}},
		preloadlist.Bulk1Year,
	},

	/******** errors and warnings ********/

	{
		"missing preload, >10 years, policy: 1 year",
		"max-age=315360001; includeSubDomains",
		Issues{
			Errors: []Issue{{Code: "header.preloadable.preload.missing"}},
			Warnings: []Issue{{
				Code:    "header.preloadable.max_age.over_10_years",
				Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
			}},
		},
		preloadlist.Bulk1Year,
	},
	{
		"missing preload, >10 years, policy: 18 weeks",
		"max-age=315360001; includeSubDomains",
		Issues{
			Errors: []Issue{{Code: "header.preloadable.preload.missing"}},
			Warnings: []Issue{{
				Code:    "header.preloadable.max_age.over_10_years",
				Message: "FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value.",
			}},
		},
		preloadlist.Bulk18Weeks,
	},
}

func TestEligibleHeaderString(t *testing.T) {
	for _, tt := range eligibleHeaderStringTests {
		issues := EligibleHeaderString(tt.header, tt.policy)
		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
	}
}

var removableHeaderStringTests = []struct {
	description    string
	header         string
	expectedIssues Issues
}{

	/******** no issues ********/

	{
		"max-age only",
		"max-age=315360001",
		Issues{},
	},
	{
		"max-age=0",
		"max-age=0",
		Issues{},
	},
	{
		"max-age and includeSubDomains",
		"max-age=315360001; includeSubDomains",
		Issues{},
	},

	/******** errors ********/

	{
		"includeSubDomains only",
		"includeSubDomains",
		Issues{Errors: []Issue{{Code: "header.removable.missing.max_age"}}},
	},
	{
		"max-age missing",
		"includeSubDomains",
		Issues{Errors: []Issue{{Code: "header.removable.missing.max_age"}}},
	},
	{
		"empty header",
		"includeSubDomains",
		Issues{Errors: []Issue{{Code: "header.removable.missing.max_age"}}},
	},
	{
		"preload present",
		"max-age=315360001; includeSubDomains; preload",
		Issues{Errors: []Issue{{Code: "header.removable.contains.preload"}}},
	},
	{
		"preload only",
		"preload",
		Issues{
			Errors: []Issue{
				{Code: "header.removable.contains.preload"},
				{Code: "header.removable.missing.max_age"},
			},
		},
	},
}

func TestRemovableHeaderString(t *testing.T) {
	for _, tt := range removableHeaderStringTests {
		issues := RemovableHeaderString(tt.header)
		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
	}
}
