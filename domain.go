package hstspreload

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	// dialTimeout specifies the amount of time that TCP or TLS connections
	// can take to complete.
	dialTimeout = 10 * time.Second
)

// dialer is a global net.Dialer that's used whenever making TLS connections in
// order to enforce dialTimeout.
var dialer = net.Dialer{
	Timeout: dialTimeout,
}

var clientWithTimeout = http.Client{
	Timeout: dialTimeout,
}

// List of eTLDs for which:
// - `www` subdomains are commonly available over HTTP, but
// - site owners have no way to serve valid HTTPS on the `www` subdomain.
//
// We whitelist such eTLDs to waive the `www` subdomain requirement.
var whitelistedWWWeTLDs = map[string]bool{
	"appspot.com": true,
}

// PreloadableDomain checks whether the domain passes HSTS preload
// requirements for Chromium. This includes:
//
// - Serving a single HSTS header that passes header requirements.
//
// - Using TLS settings that will not cause new problems for
// Chromium/Chrome users. (Example of a new problem: a missing intermediate certificate
// will turn an error page from overrideable to non-overridable on
// some mobile devices.)
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func PreloadableDomain(domain string) (header *string, issues Issues) {
	header, issues, _ = PreloadableDomainResponse(domain)
	return header, issues
}

// PreloadableDomainResponse is like PreloadableDomain, but also returns
// the initial response over HTTPS.
func PreloadableDomainResponse(domain string) (header *string, issues Issues, resp *http.Response) {
	// Check domain format issues first, since we can report something
	// useful even if the other checks fail.
	issues = combineIssues(issues, checkDomainFormat(domain))
	if len(issues.Errors) > 0 {
		return header, issues, nil
	}

	// We don't currently allow automatic submissions of subdomains.
	levelIssues := preloadableDomainLevel(domain)
	issues = combineIssues(issues, levelIssues)

	// Start with an initial probe, and don't do the follow-up checks if
	// we can't connect.
	resp, respIssues := getResponse(domain)
	issues = combineIssues(issues, respIssues)
	if len(respIssues.Errors) == 0 {
		issues = combineIssues(issues, checkChain(*resp.TLS))
		issues = combineIssues(issues, checkCipherSuite(*resp.TLS))

		preloadableResponse := make(chan Issues)
		httpRedirectsGeneral := make(chan Issues)
		httpFirstRedirectHSTS := make(chan Issues)
		httpsRedirects := make(chan Issues)
		www := make(chan Issues)

		// PreloadableResponse
		go func() {
			var preloadableIssues Issues
			header, preloadableIssues = PreloadableResponse(resp)
			preloadableResponse <- preloadableIssues
		}()

		// checkHTTPRedirects
		go func() {
			general, firstRedirectHSTS := preloadableHTTPRedirects(domain)
			httpRedirectsGeneral <- general
			httpFirstRedirectHSTS <- firstRedirectHSTS
		}()

		// checkHTTPSRedirects
		go func() {
			httpsRedirects <- preloadableHTTPSRedirects(domain)
		}()

		// checkWWW
		go func() {
			eTLD, _ := publicsuffix.PublicSuffix(domain)

			// Skip the WWW check if the domain is not eTLD+1, or if the
			// eTLD is whitelisted.
			if len(levelIssues.Errors) != 0 || whitelistedWWWeTLDs[eTLD] {
				www <- Issues{}
			} else {
				www <- checkWWW(domain)
			}
		}()

		// Combine the issues in deterministic order.
		preloadableResponseIssues := <-preloadableResponse
		issues = combineIssues(issues, preloadableResponseIssues)
		issues = combineIssues(issues, <-httpRedirectsGeneral)
		// If there are issues with the HSTS header in the main
		// PreloadableResponse() check, it is redundant to report
		// them in the response after redirecting from HTTP.
		firstRedirectHSTS := <-httpFirstRedirectHSTS // always receive the value, to avoid leaking a goroutine
		if len(preloadableResponseIssues.Errors) == 0 {
			issues = combineIssues(issues, firstRedirectHSTS)
		}
		issues = combineIssues(issues, <-httpsRedirects)
		issues = combineIssues(issues, <-www)
	}

	return header, issues, resp
}

// RemovableDomain checks whether the domain satisfies the requirements
// for being removed from the Chromium preload list:
//
// - Serving a single valid HSTS header.
//
// - The header must not contain the `preload` directive..
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func RemovableDomain(domain string) (header *string, issues Issues) {
	resp, respIssues := getResponse(domain)
	issues = combineIssues(issues, respIssues)
	if len(respIssues.Errors) == 0 {
		var removableIssues Issues
		header, removableIssues = RemovableResponse(resp)
		issues = combineIssues(issues, removableIssues)
	}

	return header, issues
}

func getResponse(domain string) (*http.Response, Issues) {
	issues := Issues{}

	// Try #1
	resp, err := getFirstResponse("https://" + domain)
	if err == nil {
		return resp, issues
	}

	// Try #2
	resp, err = getFirstResponse("https://" + domain)
	if err == nil {
		return resp, issues
	}

	// Check if ignoring cert issues works.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	resp, err = getFirstResponseWithTransport("https://"+domain, transport)
	if err == nil {
		return resp, issues.addErrorf(
			IssueCode("domain.tls.invalid_cert_chain"),
			"Invalid Certificate Chain",
			"https://%s uses an incomplete or "+
				"invalid certificate chain. Check out your site at "+
				"https://www.ssllabs.com/ssltest/",
			domain,
		)
	}

	return resp, issues.addErrorf(
		IssueCode("domain.tls.cannot_connect"),
		"Cannot connect using TLS",
		"We cannot connect to https://%s using TLS (%q).",
		domain,
		err,
	)
}

func checkDomainFormat(domain string) Issues {
	issues := Issues{}

	if strings.HasPrefix(domain, ".") {
		return issues.addErrorf(
			IssueCode("domain.format.begins_with_dot"),
			"Invalid domain name",
			"Please provide a domain that does not begin with `.`")
	}
	if strings.HasSuffix(domain, ".") {
		return issues.addErrorf(
			IssueCode("domain.format.ends_with_dot"),
			"Invalid domain name",
			"Please provide a domain that does not end with `.`")
	}
	if strings.Index(domain, "..") != -1 {
		return issues.addErrorf(
			IssueCode("domain.format.contains_double_dot"),
			"Invalid domain name",
			"Please provide a domain that does not contain `..`")
	}

	ps, _ := publicsuffix.PublicSuffix(domain)
	if ps == domain {
		return issues.addErrorf(
			IssueCode("domain.format.public_suffix"),
			"Domain is a TLD or public suffix",
			"You have entered a public suffix (ccTLD, gTLD, or other domain listed at "+
				"https://publicsuffix.org/), which cannot be submitted through this website. "+
				"If you intended to query for a normal website, make sure to enter all of its labels "+
				"(e.g. `example.com` rather than `example` or `com`). If you operate a TLD "+
				"or public suffix and are interested in preloading HSTS for it, "+
				"please see https://hstspreload.org/#tld")
	}

	domain = strings.ToLower(domain)
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}

		return issues.addErrorf("domain.format.invalid_characters", "Invalid domain name", "Please provide a domain using valid characters (letters, numbers, dashes, dots).")
	}

	return issues
}

func preloadableDomainLevel(domain string) Issues {
	issues := Issues{}

	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return issues.addErrorf("internal.domain.name.cannot_compute_etld1", "Internal Error", "Could not compute eTLD+1.")
	}

	if eTLD1 != domain {
		return issues.addErrorf(
			IssueCode("domain.is_subdomain"),
			"Subdomain",
			"`%s` is a subdomain. Please preload `%s` instead. "+
				"(Due to the size of the preload list and the behaviour of "+
				"cookies across subdomains, we only accept automated preload list "+
				"submissions of whole registered domains.)",
			domain,
			eTLD1,
		)
	}

	return issues
}

func checkWWW(host string) Issues {
	issues := Issues{}

	hasWWW := false
	if conn, err := net.DialTimeout("tcp", "www."+host+":443", dialTimeout); err == nil {
		hasWWW = true
		if err = conn.Close(); err != nil {
			return issues.addErrorf(
				"internal.domain.www.first_dial.no_close",
				"Internal error",
				"Error while closing a connection to %s: %s",
				"www."+host,
				err,
			)
		}
	}

	if hasWWW {
		wwwConn, err := tls.DialWithDialer(&dialer, "tcp", "www."+host+":443", nil)
		if err != nil {
			return issues.addErrorf(
				IssueCode("domain.www.no_tls"),
				"www subdomain does not support HTTPS",
				"Domain error: The www subdomain exists, but we couldn't connect to it using HTTPS (%q). "+
					"Since many people type this by habit, HSTS preloading would likely "+
					"cause issues for your site.",
				err,
			)
		}
		if err = wwwConn.Close(); err != nil {
			return issues.addErrorf(
				"internal.domain.www.second_dial.no_close",
				"Internal error",
				"Error while closing a connection to %s: %s",
				"www."+host,
				err,
			)
		}
	}

	return issues
}
