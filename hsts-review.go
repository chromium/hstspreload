// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"
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

type result struct {
	name string
	err  error
}

type resultList []result

func (list resultList) Len() int {
	return len(list)
}

func (list resultList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list resultList) Less(i, j int) bool {
	return list[i].name < list[j].name
}

func do() bool {
	fmt.Printf("Downloading pending entries... ")
	pendingReply, err := http.Get("https://hstspreload.appspot.com/pending")
	if err != nil {
		fmt.Printf("%s\n", err)
		return false
	}
	defer pendingReply.Body.Close()

	if pendingReply.StatusCode != 200 {
		fmt.Printf("status %d (%s)\n", pendingReply.StatusCode, pendingReply.Status)
		return false
	}

	pendingBody, err := ioutil.ReadAll(pendingReply.Body)
	if err != nil {
		fmt.Printf("%s\n", err)
		return false
	}

	pendingJson := []byte("[")
	pendingJson = append(pendingJson, pendingBody[:len(pendingBody)-2]...)
	pendingJson = append(pendingJson, ']')

	var hosts []struct {
		Name string
	}
	if err := json.Unmarshal(pendingJson, &hosts); err != nil {
		fmt.Printf("%s\n", err)
		return false
	}

	fmt.Printf("%d pending hosts\n", len(hosts))

	output := make(chan result)
	input := make(chan string, len(hosts))
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go worker(output, input, &wg)
	}

	for _, host := range hosts {
		input <- host.Name
	}
	close(input)

	var results []result
	for len(results) < len(hosts) {
		results = append(results, <-output)
		fmt.Printf(".")
	}
	wg.Wait()
	fmt.Printf("\n")

	type SetMessageJSON struct {
		Name    string
		Message string
	}
	var messages []SetMessageJSON

	for _, result := range results {
		if result.err != nil {
			messages = append(messages, SetMessageJSON{result.name, result.err.Error()})
		}
	}

	if len(messages) > 0 {
		messagesJSON, err := json.MarshalIndent(messages, "", "  ")
		if err != nil {
			panic(err)
		}

		fmt.Printf("Paste this into https://hstspreload.appspot.com/setmessages:\n\n%s\n\n", string(messagesJSON))
	}

	sort.Sort(resultList(results))

	for _, result := range results {
		if result.err == nil {
			fmt.Printf("    { \"name\": %q, \"include_subdomains\": true, \"mode\": \"force-https\" },\n", result.name)
		}
	}

	return true
}

func worker(out chan result, in chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for host := range in {
		check(out, host)
	}
}

// isConnectionRefused returns true if err is an error from net/http that was
// caused because the TCP connection was refused.
func isConnectionRefused(err error) bool {
	urlErr, ok := err.(*url.Error)
	if !ok {
		return false
	}

	netErr, ok := urlErr.Err.(*net.OpError)
	if !ok {
		return false
	}

	if netErr.Op != "dial" {
		return false
	}

	syscallErr, ok := netErr.Err.(*os.SyscallError)
	if !ok {
		return false
	}

	return syscallErr.Err == syscall.ECONNREFUSED
}

func check(out chan result, host string) {
	conn, err := tls.DialWithDialer(&dialer, "tcp", host+":443", nil)
	if err != nil {
		out <- result{host, fmt.Errorf("Cannot connect using TLS (%q). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://ssllabs.com.", err)}
		return
	}
	chain := certChain(conn.ConnectionState())
	conn.Close()

	if firstSHA1, ok := findPropertyInChain(isSHA1, chain); ok && chain[0].NotAfter.Year() >= 2016 {
		out <- result{host, fmt.Errorf("One or more of the certificates in your certificate chain is signed with SHA-1, but the leaf certificate extends into 2016. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of %q.)", firstSHA1.Subject.CommonName)}
		return
	}

	if firstECDSA, ok := findPropertyInChain(isECDSA, chain); ok {
		// There's an ECDSA certificate. Allow it if HTTP redirects to
		// HTTPS with ECDSA or if port 80 is closed.
		resp, err := http.Get("http://" + host)

		var ecdsaOk bool
		var redirectMsg string

		if err == nil {
			if resp.TLS != nil {
				_, ecdsaOk = findPropertyInChain(isECDSA, certChain(*resp.TLS))
				if !ecdsaOk {
					redirectMsg = fmt.Sprintf("HTTP redirected to %q, but that site doesn't have an ECDSA certificate", resp.Request.URL)
				}
			} else {
				redirectMsg = fmt.Sprintf("HTTP didn't redirect to an HTTPS URL")
			}
			resp.Body.Close()
		} else if isConnectionRefused(err) {
			ecdsaOk = true
		} else {
			redirectMsg = fmt.Sprintf("Looking for a redirect from HTTP resulted in an error: %q", err)
		}

		if !ecdsaOk {
			out <- result{host, fmt.Errorf("One or more of the certificates in your certificate chain use ECDSA. However, ECDSA can't be handled on Windows XP so adding your site would break it on that platform. If you don't care about Windows XP, you can have a blanket redirect from HTTP to HTTPS. (The first ECDSA certificate found has a common-name of %q. %s)", firstECDSA.Subject.CommonName, redirectMsg)}
			return
		}
	}

	hasWWW := false
	if conn, err := net.DialTimeout("tcp", "www."+host+":443", dialTimeout); err == nil {
		hasWWW = true
		conn.Close()
	}

	if hasWWW {
		wwwConn, err := tls.DialWithDialer(&dialer, "tcp", "www."+host+":443", nil)
		if err != nil {
			out <- result{host, fmt.Errorf("The www subdomain exists, but we couldn't connect to it (%q). Since many people type this by habit, HSTS preloading would likely cause issues for your site.", err)}
			return
		}
		wwwConn.Close()
	}

	out <- result{host, nil}
}

func certChain(connState tls.ConnectionState) []*x509.Certificate {
	chain := connState.VerifiedChains[0]
	return chain[:len(chain)-1]
}

func findPropertyInChain(pred func(*x509.Certificate) bool, chain []*x509.Certificate) (*x509.Certificate, bool) {
	for _, cert := range chain {
		if pred(cert) {
			return cert, true
		}
	}

	return nil, false
}

func isSHA1(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func isECDSA(cert *x509.Certificate) bool {
	return cert.PublicKeyAlgorithm == x509.ECDSA
}

func main() {
	ok := do()
	if !ok {
		os.Exit(1)
	}
}
