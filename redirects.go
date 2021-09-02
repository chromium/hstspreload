package hstspreload

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	// The maximum number of redirects when you visit the root path of the
	// domain over HTTP or HTTPS.
	maxRedirects = 3
	httpsScheme  = "https"
)

// preloadableHTTPRedirects checks for two kinds of issues:
//
// 1. General HTTP redirect issues that should always be reported.
//
// 2. Issues where the first redirect does not have HSTS
//
// It is often extra noise to report issues related to #2, so we return
// firstRedirectHSTS separately and allow the caller to decide whether
// to use or ignore those issues.
func preloadableHTTPRedirects(domain string) (general, firstRedirectHSTS Issues) {
	return preloadableHTTPRedirectsURL("http://"+domain, domain)
}

func preloadableHTTPSRedirects(domain string) Issues {
	return preloadableHTTPSRedirectsURL("https://" + domain)
}

func preloadableRedirectChain(initialURL string, chain []*url.URL) Issues {
	issues := Issues{}

	for i, u := range chain {
		if u.Scheme != httpsScheme {
			if i == 0 {
				return issues.addErrorf(
					IssueCode("redirects.insecure.initial"),
					"Insecure redirect",
					"`%s` redirects to an insecure page: `%s`", initialURL, u)
			}

			return issues.addErrorf(
				IssueCode("redirects.insecure.subsequent"),
				"Insecure redirect",
				"`%s` redirects to an insecure page on redirect #%d: `%s`", initialURL, i+1, u)
		}
	}
	return issues
}

// `cont` indicates whether the scan should continue.
func checkHSTSOverHTTP(initialURL string) (issues Issues, cont bool) {
	issues = Issues{}

	resp, err := getFirstResponse(initialURL)
	if err != nil {
		return Issues{}.addWarningf(
			"redirects.http.does_not_exist",
			"Unavailable over HTTP",
			"The site appears to be unavailable over plain HTTP (%s). "+
				"This can prevent users without a freshly updated modern browser from connecting to the site when they "+
				"visit a URL with the http:// scheme (or with an unspecified scheme). "+
				"However, this is okay if the site does not wish to support those users.",
			initialURL,
		), false
	}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	if len(resp.Header[key]) != 0 {
		return issues.addWarningf(
			IssueCode("redirects.http.useless_header"),
			"Unnecessary HSTS header over HTTP",
			"The HTTP page at %s sends an HSTS header. This has no effect over HTTP, and should be removed.",
			initialURL,
		), true
	}

	return issues, true
}

// Taking a URL allows us to test more easily. Use preloadableHTTPRedirects()
// where possible.
func preloadableHTTPRedirectsURL(initialURL string, domain string) (general, firstRedirectHSTS Issues) {
	general, cont := checkHSTSOverHTTP(initialURL)
	if !cont {
		return general, Issues{}
	}

	chain, preloadableRedirectsIssues := preloadableRedirects(initialURL)
	general = combineIssues(general, preloadableRedirectsIssues)
	if len(chain) == 0 {
		return general.addErrorf(
			IssueCode("redirects.http.no_redirect"),
			"No redirect from HTTP",
			"`%s` does not redirect to `%s`.",
			initialURL,
			"https://"+domain,
		), firstRedirectHSTS
	}

	if chain[0].Scheme == httpsScheme && chain[0].Hostname() == domain {
		// Check for HSTS on the first redirect.
		resp, err := getFirstResponse(chain[0].String())
		if err != nil {
			// We cannot connect this time. This error has high priority,
			// so return immediately and allow it to mask other errors.
			return general, firstRedirectHSTS.addErrorf(
				IssueCode("redirects.http.first_redirect.invalid"),
				"Invalid redirect",
				"`%s` redirects to `%s`, which we could not connect to: %s",
				initialURL,
				chain[0],
				err,
			)
		}
		_, redirectHSTSIssues := PreloadableResponse(resp)
		if len(redirectHSTSIssues.Errors) > 0 {
			firstRedirectHSTS = firstRedirectHSTS.addErrorf(
				IssueCode("redirects.http.first_redirect.no_hsts"),
				"HTTP redirects to a page without HSTS",
				"`%s` redirects to `%s`, which does not serve a HSTS header that satisfies preload conditions. First error: %s",
				initialURL,
				chain[0],
				redirectHSTSIssues.Errors[0].Summary,
			)
		}

		general = combineIssues(general, preloadableRedirectChain(initialURL, chain))
		return general, firstRedirectHSTS
	}

	if chain[0].Hostname() == "www."+domain {
		// For simplicity, we use the same message for two cases:
		// - http://example.com -> http://www.example.com
		// - http://example.com -> https://www.example.com
		return general.addErrorf(
			IssueCode("redirects.http.www_first"),
			"HTTP redirects to www first",
			"`%s` (HTTP) should immediately redirect to `%s` (HTTPS) "+
				"before adding the www subdomain. Right now, the first redirect is to `%s`. "+
				"The extra redirect is required to ensure that any browser which supports HSTS will "+
				"record the HSTS entry for the top level domain, not just the subdomain.",
			initialURL,
			"https://"+domain,
			chain[0],
		), firstRedirectHSTS
	}

	return general.addErrorf(
		IssueCode("redirects.http.first_redirect.insecure"),
		"HTTP does not redirect to HTTPS",
		"`%s` (HTTP) redirects to `%s`. The first redirect "+
			"from `%s` should be to a secure page on the same host (`%s`).",
		initialURL,
		chain[0],
		initialURL,
		"https://"+domain,
	), firstRedirectHSTS
}

// Taking a URL allows us to test more easily. Use preloadableHTTPSRedirects()
// where possible.
func preloadableHTTPSRedirectsURL(initialURL string) Issues {
	chain, issues := preloadableRedirects(initialURL)
	return combineIssues(issues, preloadableRedirectChain(initialURL, chain))
}

func preloadableRedirects(initialURL string) (chain []*url.URL, issues Issues) {
	var redirectChain []*url.URL
	tooManyRedirects := errors.New("TOO_MANY_REDIRECTS")

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL)

			if len(redirectChain) > maxRedirects {
				return tooManyRedirects
			}

			return nil
		},
		Timeout: dialTimeout,
	}
	req, err := http.NewRequest("GET", initialURL, nil)
	if err != nil {
		return nil, issues
	}

	req.Header.Set("User-Agent", "hsts-preload-bot")
	_, err = client.Do(req)

	if err != nil {
		if strings.HasSuffix(err.Error(), tooManyRedirects.Error()) {
			issues = issues.addErrorf(
				IssueCode("redirects.too_many"),
				"Too many redirects",
				"There are more than %d redirects starting from `%s`.", maxRedirects, initialURL)
		} else {
			issues = issues.addErrorf(
				IssueCode("redirects.follow_error"),
				"Error following redirects",
				"Redirect error: %s", err.Error())
		}
	}

	return redirectChain, issues
}
