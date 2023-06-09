package hstspreload

import (
	"encoding/json"
	"fmt"
	"log"

	preloadlist "github.com/chromium/hstspreload/chromium/preloadlist"
)

// Defines a structure to hold the json contents. The struct attributes come from the json file
type Domain struct {
	Name       string `json:"name"`
	Policy     string `json:"policy"`
	Mode       string `json:"mode"`
	Subdomains bool   `json:"include_subdomains"`
}

func main() {
	// Gets a preload list of domains
	prealoadList, listErr := preloadlist.NewFromLatest()
	if listErr != nil {
		err := fmt.Sprintf(
			"Internal error: could not retrieve latest preload list. (%s)\n",
			listErr,
		)

		// will change the format for logging an error in the future? Any ideas?
		// Do I need to treat this function as an API?
		log.Fatal(err)
		return
	}
	var actualPreload []preloadlist.Entry
	for _, entry := range prealoadList.Entries {
		if entry.Mode == preloadlist.ForceHTTPS {
			actualPreload = append(actualPreload, entry)
		}
	}

	// creates a slice for removable-eligible domains to be held in and
	// parses the JSON data
	var domains []Domain
	if err := json.Unmarshal(data, &domains); err != nil {
		log.Fatal(err)
	}

	// defines domain slices to hold bulk-18-weeks and bulk-1-year domains
	// NOTE THIS IS THE MEANS OF STORING DOMAINS UNTIL WE DEFINE A DATASTORE
	var domains18weeks []string
	var domains1year []string

	// Iterates over the objects and filters them by their policy, if the
	// policy is "custom" we don't do anything
	for _, domain := range domains {
		if domain.Policy == "bulk-18-weeks" {
			domains18weeks = append(domains18weeks, domain.Name)
		}
		if domain.Policy == "bulk-1-year" {
			domains1year = append(domains1year, domain.Name)
		}
	}
}
