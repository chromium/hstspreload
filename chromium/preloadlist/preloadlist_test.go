package preloadlist

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestIndexing(t *testing.T) {
	list := PreloadList{
		Entries: []Entry{
			{
				Name:              "garron.NET",
				Mode:              "force-https",
				IncludeSubDomains: true,
			},
			{
				Name:              "example.com",
				Mode:              "",
				IncludeSubDomains: false,
			},
			{
				Name:              "bar",
				Mode:              "force-https",
				IncludeSubDomains: true,
			},
		},
	}

	idx := list.Index()

	if len(idx.index) != 3 {
		t.Errorf("Map has the wrong number of entries.")
	}

	_, ok := idx.Get("example")
	if ok != EntryNotFound {
		t.Errorf("Entry should not be present.")
	}

	entry, ok := idx.Get("GARRON.net")
	if ok != ExactEntryFound {
		t.Errorf("Entry should be present.")
	}
	if entry.Mode != "force-https" {
		t.Errorf("Map has invalid entry.")
	}

	entry, ok = idx.Get("www.garron.net")
	if ok != AncestorEntryFound {
		t.Errorf("Ancestor entry should be present.")
	}
	if entry.Name != "garron.NET" {
		t.Errorf("Wrong ancestor entry found.")
	}
	if !entry.IncludeSubDomains {
		t.Errorf("Ancestor entry does not include subdomains.")
	}

	entry, ok = idx.Get("test.example.com")
	if ok == AncestorEntryFound {
		t.Errorf("Ancestor entry found, but it does not include subdomains.")
	}
	if entry.IncludeSubDomains {
		t.Errorf("Ancestory entry should not include subdomains.")
	}

	entry, ok = idx.Get("foo.bar")
	if ok != AncestorEntryFound {
		t.Errorf("Ancestor entry should be present.")
	}
	if entry.Name != "bar" || entry.Mode != "force-https" {
		t.Errorf("Wrong ancestor entry found.")
	}
	if !entry.IncludeSubDomains {
		t.Errorf("Ancestor entry does not include subdomains.")
	}

	entry, ok = idx.Get("bar")
	if ok != ExactEntryFound {
		t.Errorf("Entry should be present.")
	}
	if entry.Name != "bar" || entry.Mode != "force-https" || !entry.IncludeSubDomains {
		t.Errorf("Wrong entry found.")
	}
}

func TestNewFromLatest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test to avoid preload list download.")
	}

	list, err := NewFromLatest()
	if err != nil {
		t.Errorf("Could not retrieve preload list.")
	}

	firstEntry := list.Entries[0]
	if firstEntry.Name != "pinningtest.appspot.com" {
		t.Errorf("First entry of preload list does not have the expected name.")
	}
}

func TestNewFromChromiumURL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test to avoid preload list download.")
	}

	list, err := NewFromChromiumURL("https://chromium.googlesource.com/chromium/src/+/4f587d7d4532287308715d824d19e7465c9f663e/net/http/transport_security_state_static.json?format=TEXT")
	if err != nil {
		t.Error(err)
	}
	if len(list.Entries) != 3558 {
		t.Errorf("Wrong number of entries: %d", len(list.Entries))
	}
}

var (
	testJSON = `{
  "entries": [
  	// This is a comment.
    {"name": "garron.net", "include_subdomains": true, "mode": "force-https"},
    {"name": "example.com", "include_subdomains": false, "mode": "force-https"},
    {"name": "gmail.com", "mode": "force-https"},

    // Line above intentionally left blank.
    {"name": "google.com"},
    {"name": "pinned.badssl.com", "pins": "pinnymcpinnedkey"}
  ]
}`
	testParsed = PreloadList{Entries: []Entry{
		{"garron.net", "force-https", true, ""},
		{"example.com", "force-https", false, ""},
		{"gmail.com", "force-https", false, ""},
		{"google.com", "", false, ""},
		{"pinned.badssl.com", "", false, ""}},
	}
)

func TestNewFromFile(t *testing.T) {
	f, err := ioutil.TempFile("", "preloadlist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write([]byte(testJSON)); err != nil {
		t.Fatal(err)
	}

	list, err := NewFromFile(f.Name())
	if err != nil {
		t.Fatalf("Could not read preload list. %s", err)
	}

	if !reflect.DeepEqual(list, testParsed) {
		t.Errorf("Parsed list does not match expected. %#v", list)
	}
}
