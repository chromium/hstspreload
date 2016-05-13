package main

import "github.com/chromium/hstspreload"

const (
	parallelism = 10
)

// A Result holds the outcome of PreloadableDomain() for a given Domain.
type Result struct {
	Domain       string                 `json:"domain"`
	Header       string                 `json:"header,omitempty"`
	ParsedHeader hstspreload.HSTSHeader `json:"parsed_header,omitempty"`
	Issues       hstspreload.Issues     `json:"issues"`
}

func worker(in chan string, out chan Result) {
	for d := range in {

		header, issues := hstspreload.PreloadableDomain(d)

		r := Result{
			Domain: d,
			Issues: issues,
		}
		if header != nil {
			r.Header = *header
			ParsedHeader, _ := hstspreload.ParseHeaderString(*header)
			r.ParsedHeader = ParsedHeader
		}

		out <- r
	}
}

// BatchPreloadable runs hstspreload.PreloadableDomain() over the given domains
// in parallel, and returns the results in an arbitrary order.
func BatchPreloadable(domains []string) chan Result {
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
