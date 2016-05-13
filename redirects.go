package hstspreload

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
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

// Taking a URL allows us to test more easily. Use preloadableHTTPRedirects()
// where possible.
func preloadableHTTPRedirectsURL(initialURL string, domain string) (general, firstRedirectHSTS Issues) {
	chain, issues := preloadableRedirects(initialURL)
	if len(chain) == 0 {
		return issues.addErrorf(
			IssueCode("redirects.http.no_redirect"),
			"No redirect from HTTP",
			"`%s` does not redirect to `%s`.",
			initialURL,
			"https://"+domain,
		), firstRedirectHSTS
	}

	if chain[0].Scheme == httpsScheme && chain[0].Host == domain {
		// Check for HSTS on the first redirect.
		resp, err := clientWithTimeout.Get(chain[0].String())
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

	if chain[0].Host == "www."+domain {
		// For simplicity, we use the same message for two cases:
		// - http://example.com -> http://www.example.com
		// - http://example.com -> https://www.example.com
		return issues.addErrorf(
			IssueCode("redirects.http.www_first"),
			"HTTP redirects to www first",
			"`%s` (HTTP) should immediately redirect to `%s` (HTTPS) "+
				"before adding the www subdomain. Right now, the first redirect is to `%s`.",
			initialURL,
			"https://"+domain,
			chain[0],
		), firstRedirectHSTS
	}

	return issues.addErrorf(
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

	_, err := client.Get(initialURL)
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
