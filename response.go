package hstspreload

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/chromium/hstspreload/chromium/preloadlist"
)

func checkSingleHeader(resp *http.Response) (header *string, issues Issues) {
	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := resp.Header[key]

	switch {
	case len(hstsHeaders) == 0:
		return nil, issues.addErrorf(
			"response.no_header",
			"No HSTS header",
			"Response error: No HSTS header is present on the response.")

	case len(hstsHeaders) > 1:
		// TODO: Give feedback on the first(last?) HSTS header?
		return nil, issues.addErrorf(
			"response.multiple_headers",
			"Multiple HSTS headers",
			"Response error: Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders))
	}

	return &hstsHeaders[0], issues
}

func checkResponse(resp *http.Response, headerCondition func(string, preloadlist.PolicyType) Issues, policy preloadlist.PolicyType) (header *string, issues Issues) {
	header, issues = checkSingleHeader(resp)
	if len(issues.Errors) > 0 {
		return nil, issues
	}

	return header, combineIssues(issues, headerCondition(*header, policy))
}

// PreloadableResponse checks whether an resp has a single HSTS header that
// passes the preload requirements.
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func PreloadableResponse(resp *http.Response) (header *string, issues Issues) {
	return checkResponse(resp, EligibleHeaderString, preloadlist.Bulk1Year)
}

// EligibleResponse checks whether an resp has a single HSTS header that
// passes the preload requirements.
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func EligibleResponse(resp *http.Response, policy preloadlist.PolicyType) (header *string, issues Issues) {
	return checkResponse(resp, EligibleHeaderString, policy)
}

// RemovableResponse checks whether an resp has a single HSTS header that
// matches the requirements for removal from the HSTS preload list.
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func RemovableResponse(resp *http.Response) (header *string, issues Issues) {
	return checkResponse(resp, func(domain string, policy preloadlist.PolicyType) Issues { return RemovableHeaderString(domain) }, preloadlist.Bulk1Year)
}

// getFirstResponse makes a GET request to `initialURL` without redirecting.
func getFirstResponse(initialURL string) (*http.Response, error) {
	return getFirstResponseWithTransport(initialURL, nil)
}

// `transport` can be `nil`.
func getFirstResponseWithTransport(initialURL string, transport *http.Transport) (*http.Response, error) {
	redirectPrevented := errors.New("REDIRECT_PREVENTED")

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirectPrevented
		},
		Timeout: dialTimeout,
	}

	if transport != nil {
		client.Transport = transport
	}

	isRedirectPrevented := func(err error) bool {
		urlError, ok := err.(*url.Error)
		return ok && urlError.Err == redirectPrevented
	}

	req, err := http.NewRequest("GET", initialURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "hstspreload-bot")
	resp, err := client.Do(req)

	if isRedirectPrevented(err) {
		return resp, nil
	}
	return resp, err
}
