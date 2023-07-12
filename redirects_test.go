package hstspreload

import (
	"net/url"
	"sync"
	"testing"
)

func chainsEqual(actual []*url.URL, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, u := range actual {
		if u.String() != expected[i] {
			return false
		}
	}
	return true
}

var tooManyRedirectsTests = []struct {
	description    string
	url            string
	expectedChain  []string
	expectedIssues Issues
}{
	{
		"almost too many redirects",
		"https://httpbin.org/redirect/3",
		[]string{"https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"},
		Issues{},
	},
	{
		"too many redirects",
		"https://httpbin.org/redirect/4",
		[]string{"https://httpbin.org/relative-redirect/3", "https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"},
		Issues{Errors: []Issue{{
			Code:    "redirects.too_many",
			Message: "There are more than 3 redirects starting from `https://httpbin.org/redirect/4`.",
		}}},
	},
}

func TestTooManyRedirects(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	for _, tt := range tooManyRedirectsTests {
		chain, issues := preloadableRedirects(tt.url)
		if !chainsEqual(chain, tt.expectedChain) {
			t.Errorf("[%s] Unexpected chain: %v", tt.description, chain)
		}

		if !issues.Match(tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldMatch, tt.description, issues, tt.expectedIssues)
		}
	}
}

func TestInsecureRedirect(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	u := "https://httpbin.org/redirect-to?url=http://httpbin.org"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{"http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := preloadableHTTPSRedirectsURL(u)
	expected := Issues{Errors: []Issue{{
		Code:    "redirects.insecure.initial",
		Message: "`https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page: `http://httpbin.org`",
	}}}
	if !httpsIssues.Match(expected) {
		t.Errorf(issuesShouldMatch, httpsIssues, expected)
	}
}

func TestIndirectInsecureRedirect(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	u := "https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{"https://httpbin.org/redirect-to?url=http://httpbin.org", "http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := preloadableHTTPSRedirectsURL(u)
	expected := Issues{Errors: []Issue{{
		Code:    "redirects.insecure.subsequent",
		Message: "`https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page on redirect #2: `http://httpbin.org`",
	}}}
	if !httpsIssues.Match(expected) {
		t.Errorf(issuesShouldMatch, httpsIssues, expected)
	}
}

func TestExplicitPortFirstRedirect(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	u := "https://tls-v1-1.badssl.com"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{"https://tls-v1-1.badssl.com:1011/"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := preloadableHTTPSRedirectsURL(u)
	expected := Issues{}
	if !httpsIssues.Match(expected) {
		t.Errorf(issuesShouldMatch, httpsIssues, expected)
	}
}

func TestHTTPUnavailable(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	u := "http://oskuro.net"
	domain := "oskuro.net"

	// Test the helper
	issues, cont := checkHSTSOverHTTP(u)
	expected := Issues{Warnings: []Issue{{
		Code:    "redirects.http.does_not_exist",
		Message: "The site appears to be unavailable over plain HTTP (http://oskuro.net). This can prevent users without a freshly updated modern browser from connecting to the site when they visit a URL with the http:// scheme (or with an unspecified scheme). However, this is okay if the site does not wish to support those users.",
	}}}
	if !issues.Match(expected) {
		t.Errorf(issuesShouldMatch, issues, expected)
	}
	if cont {
		t.Errorf("Should continue.")
	}

	// Mini integration test
	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirectsURL(u, domain)
	expected = Issues{
		Warnings: []Issue{{Code: "redirects.http.does_not_exist"}},
	}
	if !mainIssues.Match(expected) {
		t.Errorf(issuesShouldMatch, mainIssues, expected)
	}

	if !firstRedirectHSTSIssues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

func TestHSTSOverHTTP(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	u := "http://history.google.com"
	domain := "history.google.com"

	_, issues := preloadableRedirects(u)
	if !issues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	// Test the helper
	issues, cont := checkHSTSOverHTTP(u)
	expected := Issues{Warnings: []Issue{{
		Code:    "redirects.http.useless_header",
		Message: "The HTTP page at http://history.google.com sends an HSTS header. This has no effect over HTTP, and should be removed.",
	}}}
	if !issues.Match(expected) {
		t.Errorf(issuesShouldMatch, issues, expected)
	}
	if !cont {
		t.Fatalf("Should not continue.")
	}

	// Mini integration test
	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirectsURL(u, domain)
	expected = Issues{
		Errors:   []Issue{{Code: "redirects.http.first_redirect.insecure"}},
		Warnings: []Issue{{Code: "redirects.http.useless_header"}},
	}
	if !mainIssues.Match(expected) {
		t.Errorf(issuesShouldMatch, mainIssues, expected)
	}

	if !firstRedirectHSTSIssues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

func TestHTTPNoRedirect(t *testing.T) {
	skipIfShort(t)
	t.Parallel()

	u := "http://httpbin.org"
	domain := "httpbin.org"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{}) {
		t.Errorf("Unexpected chain: %v", chain)
	}

	if !issues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirectsURL(u, domain)
	expected := Issues{Errors: []Issue{{
		Code:    "redirects.http.no_redirect",
		Message: "`http://httpbin.org` does not redirect to `https://httpbin.org`.",
	}}}
	if !mainIssues.Match(expected) {
		t.Errorf(issuesShouldMatch, mainIssues, expected)
	}

	if !firstRedirectHSTSIssues.Match(Issues{}) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

type preloadableHTTPRedirectsTest struct {
	description                     string
	domain                          string
	expectedMainIssues              Issues
	expectedFirstRedirectHSTSIssues Issues
}

var preloadableHTTPRedirectsTests = []preloadableHTTPRedirectsTest{
	{
		"different host",
		"bofa.com", // http://bofa.com redirects to https://www.bankofamerica.com
		Issues{Errors: []Issue{{
			Code:    "redirects.http.first_redirect.insecure",
			Message: "`http://bofa.com` (HTTP) redirects to `https://www.bankofamerica.com/vanity/redirect.go?src=/`. The first redirect from `http://bofa.com` should be to a secure page on the same host (`https://bofa.com`).",
		}}},
		Issues{},
	},
	{
		"same origin",
		"www.wikia.com", // http://www.wikia.com redirects to http://www.wikia.com/fandom
		Issues{Errors: []Issue{{
			Code:    "redirects.http.first_redirect.insecure",
			Message: "`http://www.wikia.com` (HTTP) redirects to `http://www.wikia.com/fandom`. The first redirect from `http://www.wikia.com` should be to a secure page on the same host (`https://www.wikia.com`).",
		}}},
		Issues{},
	},
	{
		"www first and > 3 redirects",
		"blogger.com",
		Issues{
			Errors: []Issue{
				{
					Code:    "redirects.too_many",
					Message: "There are more than 3 redirects starting from `http://blogger.com`.",
				},
				{
					Code:    "redirects.http.www_first",
					Message: "`http://blogger.com` (HTTP) should immediately redirect to `https://blogger.com` (HTTPS) before adding the www subdomain. Right now, the first redirect is to `http://www.blogger.com/`. The extra redirect is required to ensure that any browser which supports HSTS will record the HSTS entry for the top level domain, not just the subdomain.",
				},
			},
		},
		Issues{},
	},
	{
		"correct origin but not HSTS",
		"sha256.badssl.com",
		Issues{},
		Issues{Errors: []Issue{{
			Code:    "redirects.http.first_redirect.no_hsts",
			Message: "`http://sha256.badssl.com` redirects to `https://sha256.badssl.com/`, which does not serve a HSTS header that satisfies preload conditions. First error: No HSTS header",
		}}},
	},
}

func TestPreloadableHTTPRedirects(t *testing.T) {
	// Skip this test because it is failing due to relying on behavior of an
	// external domain: https://github.com/chromium/hstspreload/issues/112.
	t.SkipNow()

	skipIfShort(t)
	t.Parallel()

	wg := sync.WaitGroup{}
	wg.Add(len(preloadableHTTPRedirectsTests))

	for _, tt := range preloadableHTTPRedirectsTests {
		go func(tt preloadableHTTPRedirectsTest) {
			mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects(tt.domain)

			if !mainIssues.Match(tt.expectedMainIssues) {
				t.Errorf("[%s] main issues for %s: "+issuesShouldMatch, tt.description, tt.domain, mainIssues, tt.expectedMainIssues)
			}

			if !firstRedirectHSTSIssues.Match(tt.expectedFirstRedirectHSTSIssues) {
				t.Errorf("[%s] first redirect HSTS issues for %s: "+issuesShouldMatch, tt.description, tt.domain, firstRedirectHSTSIssues, tt.expectedFirstRedirectHSTSIssues)
			}
			wg.Done()
		}(tt)
	}

	wg.Wait()
}
