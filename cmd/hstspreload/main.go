package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/chromium/hstspreload"
	"github.com/chromium/hstspreload/batch"
	"github.com/chromium/hstspreload/chromium/preloadlist"
)

func printHelp() {
	fmt.Printf(`hstspreload is a tool for checking conditions to be added to Chromium 's
HSTS preload list. See hstspreload.org for more details.

Usage:

  hstspreload command argument

The commands are:

  preloadabledomain (+d) Check the TLS configuration and headers of a domain for
                           preload requirements.
  removabledomain   (-d) Check the headers of a domain for removal requirements.
  preloadableheader (+h) Check an HSTS header for preload requirements
  removableheader   (-h) Check an HSTS header for removal requirements
  batch                  Check a batch of domains for preload requirements.
                           Reads one domain per line from stdin, and outputs
                           JSON in non-deterministic domain order.
  status                 Check the preload status of a domain
  scan-pending           Scan pending domains from hstspreload.org

Examples:

  hstspreload +d wikipedia.org
  hstspreload +h "max-age=10886400; includeSubDomains; preload"
  hstspreload -h "max-age=10886400; includeSubDomains"
  
  echo -e "wikipedia.org\nexample.com" > domains.txt
  cat domains.txt | hstspreload batch

Return code:

  0    Passed all checks.
  1    Error (failed at least one requirement).
  2    Had warnings, but passed all requirements.
  3    Invalid commandline arguments
  4    Displayed help

`)
	os.Exit(4)
}

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		printHelp()
	}
	if args[0] == "scan-pending" {
		err := ScanPending()
		if err != nil {
			fmt.Printf("%s", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if args[0] == "scan-preloaded" {
		err := ScanPreloaded()
		if err != nil {
			fmt.Printf("%s", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if args[0] == "batch" {
		handleBatch()
	}
	if len(args) < 2 {
		printHelp()
	}

	var header *string
	var issues hstspreload.Issues

	switch args[0] {
	case "+h", "preloadableheader":
		issues = preloadableHeader(args[1])

	case "-h", "removableheader":
		issues = removableHeader(args[1])

	case "+d", "preloadabledomain":
		header, issues = preloadableDomain(args[1])

	case "-d", "removabledomain":
		header, issues = removableDomain(args[1])

	case "status":
		l, err := preloadlist.NewFromLatest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		idx := l.Index()
		domain := args[1]
		state, status := idx.Get(domain)
		if status == preloadlist.EntryNotFound {
			fmt.Printf(`%s%s%s is not preloaded.

`,
				underline, domain, resetFormat)
		} else {
			fmt.Printf(`%s%s%s is preloaded:

           domain: %s%s%s
             mode: %s%s%s
includeSubDomains: %s%t%s

`,
				underline, domain, resetFormat,
				bold, state.Name, resetFormat,
				bold, state.Mode, resetFormat,
				bold, state.IncludeSubDomains, resetFormat)
		}
		os.Exit(0)

	default:
		fmt.Printf("Unknown command: %s\n", args[0])
		os.Exit(3)
	}

	// Wrap this in a function to (statically) enforce a return code.
	showResult := func() int {
		if header != nil {
			fmt.Printf("Observed header: %s%s%s\n", bold, *header, resetFormat)
		}

		fmt.Println()
		switch {
		case len(issues.Errors) > 0:
			return 1

		case len(issues.Warnings) > 0:
			return 2

		default:
			fmt.Printf("%sSatisfies requirements.%s\n\n", green, resetFormat)
			return 0
		}
	}
	exitCode := showResult()

	printList(issues.Errors, "Error", red)
	printList(issues.Warnings, "Warning", yellow)

	os.Exit(exitCode)
}

func preloadableHeader(header string) (issues hstspreload.Issues) {
	warnIfNotHeader(header)

	fmt.Printf(
		"Checking header \"%s%s%s\" for preload requirements...\n",
		bold, header, resetFormat)

	return hstspreload.PreloadableHeaderString(header)
}

func removableHeader(header string) (issues hstspreload.Issues) {
	warnIfNotHeader(header)

	fmt.Printf(
		"Checking header \"%s%s%s\" for removal requirements...\n",
		bold, header, resetFormat)

	return hstspreload.RemovableHeaderString(header)
}

func preloadableDomain(domain string) (header *string, issues hstspreload.Issues) {
	mustBeDomain(domain)

	fmt.Printf(
		"Checking domain %s%s%s for preload requirements...\n",
		underline, domain, resetFormat)

	return hstspreload.PreloadableDomain(domain)
}

func removableDomain(domain string) (header *string, issues hstspreload.Issues) {
	mustBeDomain(domain)

	fmt.Printf(
		"Checking domain %s%s%s for removal requirements...\n",
		underline, domain, resetFormat)

	return hstspreload.RemovableDomain(domain)
}

func warnIfNotHeader(str string) {
	if probablyURL(str) {
		fmt.Fprintln(os.Stderr,
			"Warning: please supply an HSTS header string (it appears you supplied a URL).")
	}
	if probablyDomain(str) {
		fmt.Fprintln(os.Stderr,
			"Warning: please supply an HSTS header string (it appears you supplied a domain).")
	}
}

func mustBeDomain(str string) {
	if probablyHeader(str) {
		fmt.Fprintln(os.Stderr,
			"Invalid argument: please supply a domain (example.com), not a header string.")
		os.Exit(3)
	}

	if probablyURL(str) {
		fmt.Fprintln(os.Stderr,
			"Invalid argument: please supply a domain (example.com) rather than a URL (https://example.com/index.html).")
		os.Exit(3)
	}
}

func probablyHeader(str string) bool {
	return strings.Contains(str, ";") || strings.Contains(str, " ")
}

func probablyURL(str string) bool {
	return strings.HasPrefix(str, "http://") ||
		strings.HasPrefix(str, "https://") ||
		strings.Contains(str, ":") ||
		strings.Contains(str, "/")
}

func probablyDomain(str string) bool {
	return strings.Contains(str, ".") && !strings.Contains(str, " ")
}

func printList(list []hstspreload.Issue, title string, fs string) {
	if len(list) == 0 {
		return
	}

	if len(list) != 1 {
		title += "s"
	}
	fmt.Printf("%s%s:%s\n", fs, title, resetFormat)

	for i, is := range list {
		fmt.Printf(
			"\n%d. %s%s%s [%s]\n%s\n",
			i+1, fs, is.Summary, resetFormat, is.Code, is.Message)
	}

	fmt.Println()
}

func handleBatch() {
	var domains []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		domains = append(domains, sc.Text())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	err := batch.Print(domains)
	if err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
