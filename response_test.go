package hstspreload

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/chromium/hstspreload/chromium/preloadlist"
)

/******** Examples. ********/

func ExamplePreloadableResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		header, issues := PreloadableResponse(resp, "bulk-1-year")
		if header != nil {
			fmt.Printf("Header: %s", *header)
		}
		fmt.Printf("Issues: %v", issues)
	}
}

/******** Response tests. ********/

var responseTests = []struct {
	function       func(resp *http.Response, policy preloadlist.PolicyType) (header *string, issues Issues)
	description    string
	hstsHeaders    []string
	expectedIssues Issues
	policy         preloadlist.PolicyType
}{

	/******** PreloadableResponse() ********/

	{
		PreloadableResponse,
		"good header",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
		"bulk-1-year",
	},
	{
		PreloadableResponse,
		"missing preload",
		[]string{"max-age=31536000; includeSubDomains"},
		Issues{Errors: []Issue{{Code: "header.preloadable.preload.missing"}}},
		"bulk-1-year",
	},
	{
		PreloadableResponse,
		"missing includeSubDomains",
		[]string{"preload; max-age=31536000"},
		Issues{Errors: []Issue{{Code: "header.preloadable.include_sub_domains.missing"}}},
		"bulk-1-year",
	},
	{
		PreloadableResponse,
		"single header, multiple errors",
		[]string{"includeSubDomains; max-age=100"},
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.preload.missing"},
				{
					Code:    "header.preloadable.max_age.below_1_year",
					Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=100.",
				},
			},
		},
		"bulk-1-year",
	},
	{
		PreloadableResponse,
		"empty header",
		[]string{""},
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.include_sub_domains.missing", Summary: "No includeSubDomains directive", Message: "The header must contain the `includeSubDomains` directive."},
				{Code: "header.preloadable.preload.missing", Summary: "No preload directive", Message: "The header must contain the `preload` directive."},
				{Code: "header.preloadable.max_age.missing", Summary: "No max-age directice", Message: "Header requirement error: Header must contain a valid `max-age` directive."},
			},
			Warnings: []Issue{{Code: "header.parse.empty", Summary: "Empty Header", Message: "The HSTS header is empty."}},
		},
		"bulk-1-year",
	},
	{
		PreloadableResponse,
		"missing header",
		[]string{},
		Issues{Errors: []Issue{{Code: "response.no_header"}}},
		"bulk-1-year",
	},
	{
		PreloadableResponse,
		"multiple headers",
		[]string{"max-age=10", "max-age=20", "max-age=30"},
		Issues{Errors: []Issue{{Code: "response.multiple_headers"}}},
		"bulk-1-year",
	},

	/******** RemovableResponse() ********/

	{
		RemovableResponse,
		"no preload",
		[]string{"max-age=15768000; includeSubDomains"},
		Issues{},
		"bulk-1-year",
	},
	{
		RemovableResponse,
		"preload present",
		[]string{"max-age=15768000; includeSubDomains; preload"},
		Issues{Errors: []Issue{{Code: "header.removable.contains.preload"}}},
		"bulk-1-year",
	},
	{
		RemovableResponse,
		"preload only",
		[]string{"preload"},
		Issues{
			Errors: []Issue{
				{Code: "header.removable.contains.preload"},
				{Code: "header.removable.missing.max_age"},
			},
		},
		"bulk-1-year",
	},

		/******** EligibleResponse() ********/
	{
		EligibleResponse,
		"good header 1 year",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
		"bulk-1-year",
	},
	{
		EligibleResponse,
		"good header 18 weeks",
		[]string{"max-age=10886400; includeSubDomains; preload"},
		Issues{},
		"bulk-18-weeks",
	},
	{
		EligibleResponse,
		"single header, multiple errors, 1 year",
		[]string{"includeSubDomains; max-age=100"},
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.preload.missing"},
				{
					Code:    "header.preloadable.max_age.below_1_year",
					Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=100.",
				},
			},
		},
		"bulk-1-year",
	},
	{
		EligibleResponse,
		"single header, multiple errors, 18 weeks",
		[]string{"includeSubDomains; max-age=100"},
		Issues{
			Errors: []Issue{
				{Code: "header.preloadable.preload.missing"},
				{
					Code:    "header.preloadable.max_age.below_18_weeks",
					Message: "The max-age must be at least 10886400 seconds (≈ 18 weeks), but the header currently only has max-age=100.",
				},
			},
		},
		"bulk-18-weeks",
	},
	{
		EligibleResponse,
		"18 week max age, 1 year",
		[]string{"max-age=10886400; includeSubDomains; preload"},
		Issues{
			Errors: []Issue{
				{
					Code:    "header.preloadable.max_age.below_1_year",
					Message: "The max-age must be at least 31536000 seconds (≈ 1 year), but the header currently only has max-age=10886400.",
				},
			},
		},
		"bulk-1-year",
	},
	{
		EligibleResponse,
		"18 week max age, 18 weeks",
		[]string{"max-age=10886400; includeSubDomains; preload"},
		Issues{},
		"bulk-18-weeks",
	},
	{
		EligibleResponse,
		"1 year max age, 1 year",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
		"bulk-1-year",
	},
	{
		EligibleResponse,
		"1 year max age, 18 weeks",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
		"bulk-18-weeks",
	},
}

func TestPreloabableResponseRemovableAndEligibleResponse(t *testing.T) {
	for _, tt := range responseTests {

		resp := &http.Response{}
		resp.Header = http.Header{}

		key := http.CanonicalHeaderKey("Strict-Transport-Security")
		for _, h := range tt.hstsHeaders {
			resp.Header.Add(key, h)
		}

		header, issues := tt.function(resp, tt.policy)

		if len(tt.hstsHeaders) == 1 {
			if header == nil {
				t.Errorf("[%s] Did not receive exactly one HSTS header", tt.description)
			} else if *header != tt.hstsHeaders[0] {
				t.Errorf(`[%s] Did not receive expected header.
			Actual: "%v"
			Expected: "%v"`, tt.description, *header, tt.hstsHeaders[0])
			}
		} else {
			if header != nil {
				t.Errorf("[%s] Did not expect a header, but received `%s`", tt.description, *header)
			}
		}

		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
	}
}
