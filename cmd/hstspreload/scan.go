package main

import (
	"encoding/json"
	"net/http"

	"github.com/chromium/hstspreload/batch"
	"github.com/chromium/hstspreload/chromium/preloadlist"
)

// ScanPending scans all pending submitted domains.
func ScanPending() error {
	domains, err := pendingDomains()
	if err != nil {
		return err
	}

	err = batch.Print(domains)
	if err != nil {
		return err
	}

	return nil
}

// ScanPreloaded scans all preloaded domains.
func ScanPreloaded() error {
	domains, err := preloadedDomains()
	if err != nil {
		return err
	}

	err = batch.Print(domains)
	if err != nil {
		return err
	}

	return nil
}

// PendingDomains gets the list of pending domains from the submission site.
func pendingDomains() ([]string, error) {
	resp, err := http.Get("https://hstspreload.org/api/v2/pending")
	if err != nil {
		return []string{}, err
	}

	var entries []preloadlist.Entry
	err = json.NewDecoder(resp.Body).Decode(&entries)
	if err != nil {
		return []string{}, err
	}

	var domains []string
	for _, entry := range entries {
		domains = append(domains, entry.Name)
	}

	return domains, nil
}

// PreloadedDomains gets the list of pending domains from the Chromium source.
func preloadedDomains() ([]string, error) {
	list, err := preloadlist.NewFromLatest()
	if err != nil {
		return []string{}, err
	}

	var domains []string
	for _, entry := range list.Entries {
		domains = append(domains, entry.Name)
	}

	return domains, nil
}
