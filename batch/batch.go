package batch

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chromium/hstspreload"
	"github.com/chromium/hstspreload/chromium/preloadlist"
)

const (
	parallelism = 100
)

// CertSummary summarizes interesting info about an X509.Certificate
// Hashes of public certs can be looked up at https://crt.sh/
type CertSummary struct {
	IssuerCommonName string    `json:"issuer_common_name"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	SHA256Hash       string    `json:"sha256_hash"`
}

// A Result holds the outcome of PreloadableDomain() for a given Domain.
type Result struct {
	Domain          string                 `json:"domain"`
	Header          string                 `json:"header,omitempty"`
	ParsedHeader    hstspreload.HSTSHeader `json:"parsed_header,omitempty"`
	Issues          hstspreload.Issues     `json:"issues"`
	LeafCertSummary CertSummary            `json:"leaf_cert_summary,omitempty"`
}

func worker(in chan string, out chan Result) {
	for d := range in {

		header, issues, resp := hstspreload.EligibleDomainResponse(d, preloadlist.Bulk1Year)

		r := Result{
			Domain: d,
			Issues: issues,
		}
		if resp != nil &&
			resp.TLS != nil &&
			resp.TLS.VerifiedChains != nil &&
			len(resp.TLS.VerifiedChains) > 0 &&
			len(resp.TLS.VerifiedChains[0]) > 0 {
			leafCert := resp.TLS.VerifiedChains[0][0]
			r.LeafCertSummary = CertSummary{
				IssuerCommonName: leafCert.Issuer.CommonName,
				NotBefore:        leafCert.NotBefore,
				NotAfter:         leafCert.NotAfter,
				SHA256Hash:       fmt.Sprintf("%x", sha256.Sum256(leafCert.Raw)),
			}
		}
		if header != nil {
			r.Header = *header
			ParsedHeader, _ := hstspreload.ParseHeaderString(*header)
			r.ParsedHeader = ParsedHeader
		}

		out <- r
	}
}

// Preloadable runs hstspreload.PreloadableDomain() over the given domains
// in parallel, and returns the results in an arbitrary order.
func Preloadable(domains []string) chan Result {
	in := make(chan string)
	out := make(chan Result)
	for i := 0; i < parallelism; i++ {
		go worker(in, out)
	}

	go func() {
		for _, d := range domains {
			in <- d
		}
	}()

	results := make(chan Result)
	go func() {
		for range domains {
			results <- (<-out)
		}
		close(in)
		close(out)
		close(results)
	}()

	return results
}

// Fprint runs BatchPreloadable on the given domains and prints the results.
// Aborts and returns an error if an error in JSON serialization is encountered..
func Fprint(w io.Writer, domains []string) error {
	fmt.Fprintln(w, "[")
	results := Preloadable(domains)
	for i := range domains {
		r := <-results
		j, err := json.MarshalIndent(r, "  ", "  ")
		if err != nil {
			return err
		}
		comma := ""
		if i != len(domains)-1 {
			comma = ","
		}
		fmt.Fprintf(w, "  %s%s\n", j, comma)
	}
	fmt.Fprintln(w, "]")

	return nil
}

// Print is a wrapper for Fprint that prints to stdout.
func Print(domains []string) error {
	return Fprint(os.Stdout, domains)
}
