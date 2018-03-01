package hstspreload

import (
	"fmt"
	"sync"
	"testing"
)

func ExamplePreloadableDomain() {
	header, issues := PreloadableDomain("wikipedia.org")
	if header != nil {
		fmt.Printf("Header: %s", *header)
	}
	fmt.Printf("Issues %v", issues)
}

/******** Utility functions tests. ********/

var testCheckDomainFormatTests = []struct {
	domain   string
	expected Issues
}{
	{".example.com",
		Issues{Errors: []Issue{{Code: "domain.format.begins_with_dot"}}},
	},
	{"example.com.",
		Issues{Errors: []Issue{{Code: "domain.format.ends_with_dot"}}},
	},
	{"example..com",
		Issues{Errors: []Issue{{Code: "domain.format.contains_double_dot"}}},
	},
	{"example",
		Issues{Errors: []Issue{{Code: "domain.format.public_suffix"}}},
	},
	{"co.uk",
		Issues{Errors: []Issue{{Code: "domain.format.public_suffix"}}},
	},
	{"example&co.com",
		Issues{Errors: []Issue{{Code: "domain.format.invalid_characters"}}},
	},
}

func TestCheckDomainFormat(t *testing.T) {
	for _, tt := range testCheckDomainFormatTests {
		issues := checkDomainFormat(tt.domain)
		if !issues.Match(tt.expected) {
			t.Errorf(issuesShouldMatch, issues, tt.expected)
		}
	}
}

var testPreloadableDomainLevel = []struct {
	domain   string
	expected Issues
}{
	{"github.io",
		Issues{Errors: []Issue{{
			Code: "internal.domain.name.cannot_compute_etld1",
		}}},
	},
	{"example.com",
		Issues{},
	},
	{"example.co.uk",
		Issues{},
	},
	{"subdomain.example.com",
		Issues{Errors: []Issue{{
			Code:    "domain.is_subdomain",
			Message: "`subdomain.example.com` is a subdomain. Please preload `example.com` instead. (Due to the size of the preload list and the behaviour of cookies across subdomains, we only accept automated preload list submissions of whole registered domains.)",
		}}},
	},
}

func TestPreloadableDomainLevel(t *testing.T) {
	for _, tt := range testPreloadableDomainLevel {
		issues := preloadableDomainLevel(tt.domain)
		if !issues.Match(tt.expected) {
			t.Errorf(issuesShouldMatch, issues, tt.expected)
		}
	}
}

/******** Real domain tests. ********/

// Avoid hitting the network for short tests.
// This gives us performant, deterministic, and offline testing.
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping domain test.")
	}
}

type preloadableDomainTest struct {
	function       func(domain string) (*string, Issues)
	description    string
	domain         string
	expectHeader   bool
	expectedHeader string
	expectedIssues Issues
}

var preloadableDomainTests = []preloadableDomainTest{

	/********* PreloadableDomain() ********/

	{
		PreloadableDomain,
		"valid HSTS",
		"wikipedia.org",
		true, "max-age=106384710; includeSubDomains; preload",
		Issues{},
	},
	{
		PreloadableDomain,
		"incomplete chain",
		"incomplete-chain.badssl.com",
		false, "",
		Issues{
			Errors: []Issue{
				{Code: "domain.is_subdomain"},
				{
					Code:    "domain.tls.invalid_cert_chain",
					Message: "https://incomplete-chain.badssl.com uses an incomplete or invalid certificate chain. Check out your site at https://www.ssllabs.com/ssltest/",
				},
			},
		},
	},
	{
		PreloadableDomain,
		"www.no_tls (not whitelisted)",
		"lgarron.github.io",
		false, "",
		Issues{
			Errors: []Issue{
				Issue{Code: "response.no_header", Summary: "No HSTS header", Message: "Response error: No HSTS header is present on the response."},
				Issue{Code: "domain.www.no_tls", Summary: "www subdomain does not support HTTPS", Message: "Domain error: The www subdomain exists, but we couldn't connect to it using HTTPS (\"x509: certificate is valid for www.github.com, *.github.com, github.com, *.github.io, github.io, *.githubusercontent.com, githubusercontent.com, not www.lgarron.github.io\"). Since many people type this by habit, HSTS preloading would likely cause issues for your site."},
			},
		},
	},
	{
		PreloadableDomain,
		"www.no_tls whitelisted",
		"hstspreload.appspot.com",
		true, "max-age=31536000; includeSubDomains; preload",
		Issues{},
	},
	{
		PreloadableDomain,
		"self-signed",
		"self-signed.badssl.com",
		false, "",
		Issues{
			Errors: []Issue{
				{Code: "domain.is_subdomain"},
				{
					Code:    "domain.tls.invalid_cert_chain",
					Message: "https://self-signed.badssl.com uses an incomplete or invalid certificate chain. Check out your site at https://www.ssllabs.com/ssltest/",
				},
			},
		},
	},
	{
		PreloadableDomain,
		"SHA-1",
		"sha1-intermediate.badssl.com",
		false, "",
		Issues{
			Errors: []Issue{
				{Code: "domain.is_subdomain"},
				{
					Code:    "domain.tls.sha1",
					Message: "One or more of the certificates in your certificate chain is signed using SHA-1. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of \"COMODO SSL CA\".)",
				},
				{Code: "response.no_header"},
			},
		},
	},
	{
		PreloadableDomain,
		"obsolete cipher suite",
		"cbc.badssl.com",
		false, "",
		Issues{
			Errors: []Issue{
				{Code: "domain.is_subdomain"},
				{Code: "response.no_header"},
			},
			Warnings: []Issue{
				{
					Code:    "tls.obsolete_cipher_suite",
					Message: "The site is using obsolete TLS settings. Check out the site at https://www.ssllabs.com/ssltest/",
				},
			},
		},
	},
	{
		PreloadableDomain,
		"subdomain",
		"en.wikipedia.org",
		true, "max-age=106384710; includeSubDomains; preload",
		Issues{Errors: []Issue{{
			Code:    "domain.is_subdomain",
			Message: "`en.wikipedia.org` is a subdomain. Please preload `wikipedia.org` instead. (Due to the size of the preload list and the behaviour of cookies across subdomains, we only accept automated preload list submissions of whole registered domains.)",
		}}},
	},
	{
		PreloadableDomain,
		"no HSTS",
		"example.com",
		false, "",
		Issues{
			Errors: []Issue{
				{Code: "response.no_header"},
				{
					Code:    "redirects.http.no_redirect",
					Message: "`http://example.com` does not redirect to `https://example.com`.",
				},
			},
		},
	},
	{
		PreloadableDomain,
		"bogus domain",
		"example.notadomain",
		false, "",
		Issues{Errors: []Issue{{Code: "domain.tls.cannot_connect"}}},
	},

	/******** RemovableDomain() ********/

	{
		RemovableDomain,
		"no header",
		"example.com",
		false, "",
		Issues{Errors: []Issue{{Code: "response.no_header"}}},
	},
	{
		RemovableDomain,
		"no preload directive",
		"hsts.badssl.com",
		true, "max-age=15768000; includeSubDomains",
		Issues{},
	},
	{
		RemovableDomain,
		"preloaded",
		"preloaded-hsts.badssl.com",
		true, "max-age=15768000; includeSubDomains; preload",
		Issues{Errors: []Issue{{Code: "header.removable.contains.preload"}}},
	},
}

func TestPreloadableDomainAndRemovableDomain(t *testing.T) {
	skipIfShort(t)
	t.Parallel()

	wg := sync.WaitGroup{}
	wg.Add(len(preloadableDomainTests))

	for _, tt := range preloadableDomainTests {
		go func(tt preloadableDomainTest) {
			header, issues := tt.function(tt.domain)

			if tt.expectHeader {
				if header == nil {
					t.Errorf("[%s] %s: Did not receive exactly one HSTS header", tt.description, tt.domain)
				} else if *header != tt.expectedHeader {
					t.Errorf(`[%s] %s: Did not receive expected header.
				Actual: "%v"
				Expected: "%v"`, tt.description, tt.domain, *header, tt.expectedHeader)
				}
			} else {
				if header != nil {
					t.Errorf("[%s] %s: Did not expect a header, but received `%s`", tt.description, tt.domain, *header)
				}
			}

			if !issues.Match(tt.expectedIssues) {
				t.Errorf("[%s] %s: "+issuesShouldMatch, tt.description, tt.domain, issues, tt.expectedIssues)
			}
			wg.Done()
		}(tt)
	}

	wg.Wait()
}
