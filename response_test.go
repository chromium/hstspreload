package hstspreload

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/chromium/hstspreload/chromium/preloadlist"
)

/******** EligibleResponse Wrappers. ********/
// EligibleResponse1Year calls EligibleResponse with a policy of 
// "bulk-1-year". Function exists for testing purposes
func eligibleResponse1Year(resp *http.Response) (header *string, issues Issues) {
	return EligibleResponse(resp, preloadlist.Bulk1Year)
}

// EligibleResponse18Weeks calls EligibleResonse with a policy of
// "bulk-18-weeks". Function exists for testing purposes
func eligibleResponse18Weeks(resp *http.Response) (header *string, issues Issues) {
	return EligibleResponse(resp, preloadlist.Bulk18Weeks)
}

/******** Examples. ********/

func ExamplePreloadableResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		header, issues := PreloadableResponse(resp)
		if header != nil {
			fmt.Printf("Header: %s", *header)
		}
		fmt.Printf("Issues: %v", issues)
	}
}

/******** Response tests. ********/

var responseTests = []struct {
	function       func(resp *http.Response) (header *string, issues Issues)
	description    string
	hstsHeaders    []string
	expectedIssues Issues
}{

	/******** PreloadableResponse() ********/

	{
		PreloadableResponse,
		"good header",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
	},
	{
		PreloadableResponse,
		"missing preload",
		[]string{"max-age=31536000; includeSubDomains"},
		Issues{Errors: []Issue{{Code: "header.preloadable.preload.missing"}}},
	},
	{
		PreloadableResponse,
		"missing includeSubDomains",
		[]string{"preload; max-age=31536000"},
		Issues{Errors: []Issue{{Code: "header.preloadable.include_sub_domains.missing"}}},
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
	},
	{
		PreloadableResponse,
		"missing header",
		[]string{},
		Issues{Errors: []Issue{{Code: "response.no_header"}}},
	},
	{
		PreloadableResponse,
		"multiple headers",
		[]string{"max-age=10", "max-age=20", "max-age=30"},
		Issues{Errors: []Issue{{Code: "response.multiple_headers"}}},
	},

	/******** RemovableResponse() ********/

	{
		RemovableResponse,
		"no preload",
		[]string{"max-age=15768000; includeSubDomains"},
		Issues{},
	},
	{
		RemovableResponse,
		"preload present",
		[]string{"max-age=15768000; includeSubDomains; preload"},
		Issues{Errors: []Issue{{Code: "header.removable.contains.preload"}}},
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
	},

		/******** EligibleResponse() ********/
	{
		eligibleResponse1Year,
		"good header 1 year",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
	},
	{
		eligibleResponse18Weeks,
		"good header 18 weeks",
		[]string{"max-age=10886400; includeSubDomains; preload"},
		Issues{},
	},
	{
		eligibleResponse1Year,
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
	},
	{
		eligibleResponse18Weeks,
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
	},
	{
		eligibleResponse1Year,
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
	},
	{
		eligibleResponse18Weeks,
		"18 week max age, 18 weeks",
		[]string{"max-age=10886400; includeSubDomains; preload"},
		Issues{},
	},
	{
		eligibleResponse1Year,
		"1 year max age, 1 year",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
	},
	{
		eligibleResponse18Weeks,
		"1 year max age, 18 weeks",
		[]string{"max-age=31536000; includeSubDomains; preload"},
		Issues{},
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

		header, issues := tt.function(resp)

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
