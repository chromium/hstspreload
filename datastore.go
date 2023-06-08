package hstspreload

import "time"

type Datastore interface {
	GetDomainState(string) DomainState
	SetDomainState(string, DomainState)
	UpdateScan(scan)
}

// DomainState represents the state stored for a domain in the datastore database
type DomainState struct {
	// Name is the key in the datastore, so we don't include it as a field
	// in the stored value.
	Name string `datastore:"-" json:"name"`
	// The Unix time this domain was scanned and the issues that arose
	Scan []scan `json:"-"`
	//  The policy under which the domain is part of the
	//  preload list. “bulk-18-weeks” or “bulk-1-year”
	Policy string `json:"policy"`
}

type scan struct {
	scanTime time.Time
	issues   []Issues
}
