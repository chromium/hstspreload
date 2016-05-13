package preloadlist

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

const (
	// ForceHTTPS indicates that all requests should be upgraded from HTTP to
	// HTTPS using the HSTS mechanism (https://tools.ietf.org/html/rfc6797).
	ForceHTTPS = "force-https"
)

// PreloadList contains a parsed form of the Chromium Preload list.
//
// The full list contains information about more than just HSTS, but only
// HSTS-related contents are currently exposed in this struct.
type PreloadList struct {
	Entries []Entry `json:"entries"`
}

// A Entry contains the data from an entry in the Chromium
// Preload list.
//
// - Name: The domain name.
//
// - Mode: The only valid non-empty value is ForceHTTPS
//
// - IncludeSubDomains: If Mode == ForceHTTPS, forces HSTS to apply to
//   all subdomains.
type Entry struct {
	Name              string `json:"name"`
	Mode              string `json:"mode"`
	IncludeSubDomains bool   `json:"include_subdomains"`
}

// IndexedEntries is case-insensitive index of
// the entries from the given PreloadList.
type IndexedEntries struct {
	index map[string]Entry
}

// Index creates an index out of the given list.
func (p PreloadList) Index() (idx IndexedEntries) {
	m := make(map[string]Entry)
	for _, entry := range p.Entries {
		d := strings.ToLower(string(entry.Name))
		m[d] = entry
	}
	return IndexedEntries{
		index: m,
	}
}

// Get acts similar to map access: it returns an entry from the index preload
// list (if it is present), along with a boolean indicating if the entry is
// present.
func (idx IndexedEntries) Get(domain string) (Entry, bool) {
	entry, ok := idx.index[strings.ToLower(domain)]
	return entry, ok
}

const (
	// LatestChromiumURL is the URL of the latest preload list in the Chromium source.
	LatestChromiumURL = "https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json?format=TEXT"
)

// Parse reads a preload list in JSON format (with certain possible comments)
// and returns a parsed version.
func Parse(r io.Reader) (PreloadList, error) {
	var list PreloadList

	jsonBytes, err := removeComments(r)
	if err != nil {
		return list, errors.New("could not decode body")
	}

	if err := json.Unmarshal(jsonBytes, &list); err != nil {
		return list, err
	}

	return list, nil
}

// removeComments reads the contents of |r| and removes any lines beginning
// with optional whitespace followed by "//"
func removeComments(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if isCommentLine(line) {
			fmt.Fprintln(&buf, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func isCommentLine(line string) bool {
	trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
	return !strings.HasPrefix(trimmed, "//")
}

// NewFromChromiumURL retrieves the latest PreloadList from a URL that returns
// the list in base 64.
func NewFromChromiumURL(u string) (PreloadList, error) {
	var list PreloadList

	client := http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := client.Get(u)
	if err != nil {
		return list, err
	}

	if resp.StatusCode != 200 {
		return list, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body := base64.NewDecoder(base64.StdEncoding, resp.Body)

	return Parse(body)
}

// NewFromLatest retrieves the latest PreloadList from the Chromium source at
// https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
//
// Note that this list may be up to 12 weeks fresher than the list used
// by the current stable version of Chrome. See
// https://www.chromium.org/developers/calendar for a calendar of releases.
func NewFromLatest() (PreloadList, error) {
	return NewFromChromiumURL(LatestChromiumURL)
}

// NewFromFile reads a PreloadList from a JSON file.
//
// In a Chromium checkout, the file is at
// src/net/http/transport_security_state_static.json
func NewFromFile(fileName string) (PreloadList, error) {
	b, err := os.Open(fileName)
	if err != nil {
		return PreloadList{}, err
	}

	return Parse(b)
}
