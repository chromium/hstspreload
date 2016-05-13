// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This program converts the information in
// transport_security_state_static.json and
// transport_security_state_static.certs into
// transport_security_state_static.h. The input files contain information about
// public key pinning and HTTPS-only sites that is compiled into Chromium.

// Run as:
// % go run transport_security_state_static_generate.go transport_security_state_static.json transport_security_state_static.certs
//
// It will write transport_security_state_static.h

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
)

// A pin represents an entry in transport_security_state_static.certs. It's a
// name associated with a SubjectPublicKeyInfo hash and, optionally, a
// certificate.
type pin struct {
	name         string
	cert         *x509.Certificate
	publicKey    *pem.Block
	spkiHash     []byte
	spkiHashFunc string // i.e. "sha256"
}

// preloaded represents the information contained in the
// transport_security_state_static.json file. This structure and the two
// following are used by the "json" package to parse the file. See the comments
// in transport_security_state_static.json for details.
type preloaded struct {
	Pinsets   []pinset `json:"pinsets"`
	Entries   []hsts   `json:"entries"`
	DomainIDs []string `json:"domain_ids"`
}

type pinset struct {
	Name      string   `json:"name"`
	Include   []string `json:"static_spki_hashes"`
	Exclude   []string `json:"bad_static_spki_hashes"`
	ReportURI string   `json:"report_uri"`
}

type hsts struct {
	Name                 string `json:"name"`
	Subdomains           bool   `json:"include_subdomains"`
	SubdomainsForPinning bool   `json:"include_subdomains_for_pinning"`
	Mode                 string `json:"mode"`
	Pins                 string `json:"pins"`
	ExpectCT             bool   `json:"expect_ct"`
	ExpectCTReportURI    string `json:"expect_ct_report_uri"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <json file> <certificates file>\n", os.Args[0])
		os.Exit(1)
	}

	if err := process(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "Conversion failed: %s\n", err.Error())
		os.Exit(1)
	}
}

func process(jsonFileName, certsFileName string) error {
	jsonFile, err := os.Open(jsonFileName)
	if err != nil {
		return fmt.Errorf("failed to open input file: %s\n", err.Error())
	}
	defer jsonFile.Close()

	jsonBytes, err := removeComments(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to remove comments from JSON: %s\n", err.Error())
	}

	var preloaded preloaded
	if err := json.Unmarshal(jsonBytes, &preloaded); err != nil {
		return fmt.Errorf("failed to parse JSON: %s\n", err.Error())
	}

	certsFile, err := os.Open(certsFileName)
	if err != nil {
		return fmt.Errorf("failed to open input file: %s\n", err.Error())
	}
	defer certsFile.Close()

	pins, err := parseCertsFile(certsFile)
	if err != nil {
		return fmt.Errorf("failed to parse certificates file: %s\n", err)
	}

	if err := checkDuplicatePins(pins); err != nil {
		return err
	}

	if err := checkCertsInPinsets(preloaded.Pinsets, pins); err != nil {
		return err
	}

	if err := checkNoopEntries(preloaded.Entries); err != nil {
		return err
	}

	if err := checkDuplicateEntries(preloaded.Entries); err != nil {
		return err
	}

	if err := checkSubdomainsFlags(preloaded.Entries); err != nil {
		return err
	}

	outFile, err := os.OpenFile("transport_security_state_static.h", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	out := bufio.NewWriter(outFile)
	writeHeader(out)
	writeDomainIDs(out, preloaded.DomainIDs)
	writeCertsOutput(out, pins)
	expectCTReportURIIds := writeExpectCTReportURIIds(out, preloaded.Entries)
	writeHSTSOutput(out, preloaded, expectCTReportURIIds)
	writeFooter(out)
	out.Flush()

	return nil
}

var newLine = []byte("\n")
var startOfCert = []byte("-----BEGIN CERTIFICATE")
var endOfCert = []byte("-----END CERTIFICATE")
var startOfPublicKey = []byte("-----BEGIN PUBLIC KEY")
var endOfPublicKey = []byte("-----END PUBLIC KEY")
var startOfSHA1 = []byte("sha1/")
var startOfSHA256 = []byte("sha256/")

// nameRegexp matches valid pin names: an uppercase letter followed by zero or
// more letters and digits.
var nameRegexp = regexp.MustCompile("[A-Z][a-zA-Z0-9_]*")

// commentRegexp matches lines that optionally start with whitespace
// followed by "//".
var commentRegexp = regexp.MustCompile("^[ \t]*//")

// removeComments reads the contents of |r| and removes any lines beginning
// with optional whitespace followed by "//"
func removeComments(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	in := bufio.NewReader(r)

	for {
		line, isPrefix, err := in.ReadLine()
		if isPrefix {
			return nil, errors.New("line too long in JSON")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if commentRegexp.Match(line) {
			continue
		}
		buf.Write(line)
		buf.Write(newLine)
	}

	return buf.Bytes(), nil
}

// parseCertsFile parses |inFile|, in the format of
// transport_security_state_static.certs. See the comments at the top of that
// file for details of the format.
func parseCertsFile(inFile io.Reader) ([]pin, error) {
	const (
		PRENAME = iota
		POSTNAME
		INCERT
		INPUBLICKEY
	)

	in := bufio.NewReader(inFile)

	lineNo := 0
	var pemCert []byte
	var pemPublicKey []byte
	state := PRENAME
	var name string
	var pins []pin

	for {
		lineNo++
		line, isPrefix, err := in.ReadLine()
		if isPrefix {
			return nil, fmt.Errorf("line %d is too long to process\n", lineNo)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading from input: %s\n", err.Error())
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		switch state {
		case PRENAME:
			name = string(line)
			if !nameRegexp.MatchString(name) {
				return nil, fmt.Errorf("invalid name on line %d\n", lineNo)
			}
			state = POSTNAME
		case POSTNAME:
			switch {
			case bytes.HasPrefix(line, startOfSHA1):
				return nil, fmt.Errorf("SHA1 hash found on line %d. Static SHA-1 pins are no longer supported", lineNo)
			case bytes.HasPrefix(line, startOfSHA256):
				hash, err := base64.StdEncoding.DecodeString(string(line[len(startOfSHA256):]))
				if err != nil {
					return nil, fmt.Errorf("failed to decode hash on line %d: %s\n", lineNo, err)
				}
				if len(hash) != 32 {
					return nil, fmt.Errorf("bad SHA256 hash length on line %d: %s\n", lineNo, err)
				}
				pins = append(pins, pin{
					name:         name,
					spkiHashFunc: "sha256",
					spkiHash:     hash,
				})
				state = PRENAME
				continue
			case bytes.HasPrefix(line, startOfCert):
				pemCert = pemCert[:0]
				pemCert = append(pemCert, line...)
				pemCert = append(pemCert, '\n')
				state = INCERT
			case bytes.HasPrefix(line, startOfPublicKey):
				pemPublicKey = pemPublicKey[:0]
				pemPublicKey = append(pemPublicKey, line...)
				pemPublicKey = append(pemPublicKey, '\n')
				state = INPUBLICKEY
			default:
				return nil, fmt.Errorf("line %d, after a name, is not a hash nor a certificate\n", lineNo)
			}
		case INCERT:
			pemCert = append(pemCert, line...)
			pemCert = append(pemCert, '\n')
			if !bytes.HasPrefix(line, endOfCert) {
				continue
			}

			block, _ := pem.Decode(pemCert)
			if block == nil {
				return nil, fmt.Errorf("failed to decode certificate ending on line %d\n", lineNo)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate ending on line %d: %s\n", lineNo, err.Error())
			}
			certName := cert.Subject.CommonName
			if len(certName) == 0 {
				certName = cert.Subject.Organization[0] + " " + cert.Subject.OrganizationalUnit[0]
			}
			if err := matchNames(certName, name); err != nil {
				return nil, fmt.Errorf("name failure on line %d: %s\n%s -> %s\n", lineNo, err, certName, name)
			}
			h := sha256.New()
			h.Write(cert.RawSubjectPublicKeyInfo)
			pins = append(pins, pin{
				name:         name,
				cert:         cert,
				spkiHashFunc: "sha256",
				spkiHash:     h.Sum(nil),
			})
			state = PRENAME
		case INPUBLICKEY:
			pemPublicKey = append(pemPublicKey, line...)
			pemPublicKey = append(pemPublicKey, '\n')
			if !bytes.HasPrefix(line, endOfPublicKey) {
				continue
			}

			rawPublicKey, _ := pem.Decode(pemPublicKey)
			if rawPublicKey == nil {
				return nil, fmt.Errorf("failed to decode public key ending on line %d\n", lineNo)
			}
			h := sha256.New()
			h.Write(rawPublicKey.Bytes)
			pins = append(pins, pin{
				name:         name,
				publicKey:    rawPublicKey,
				spkiHashFunc: "sha256",
				spkiHash:     h.Sum(nil),
			})
			state = PRENAME
		}
	}

	return pins, nil
}

// matchNames returns true if the given pin name is a reasonable match for the
// given CN.
func matchNames(name, v string) error {
	words := strings.Split(name, " ")
	if len(words) == 0 {
		return errors.New("no words in certificate name")
	}
	firstWord := words[0]
	if strings.HasSuffix(firstWord, ",") {
		firstWord = firstWord[:len(firstWord)-1]
	}
	if strings.HasPrefix(firstWord, "*.") {
		firstWord = firstWord[2:]
	}
	if pos := strings.Index(firstWord, "."); pos != -1 {
		firstWord = firstWord[:pos]
	}
	if pos := strings.Index(firstWord, "-"); pos != -1 {
		firstWord = firstWord[:pos]
	}
	if len(firstWord) == 0 {
		return errors.New("first word of certificate name is empty")
	}
	firstWord = regexp.MustCompile("[^A-Za-z0-9_]+").ReplaceAllString(firstWord, "")
	firstWord = strings.ToLower(firstWord)
	lowerV := strings.ToLower(v)
	if !strings.HasPrefix(lowerV, firstWord) {
		return fmt.Errorf("the first word of the certificate name (%s) isn't a prefix of the variable name (%s)", firstWord, lowerV)
	}

	for i, word := range words {
		if word == "Class" && i+1 < len(words) {
			if strings.Index(v, word+words[i+1]) == -1 {
				return errors.New("class specification doesn't appear in the variable name")
			}
		} else if len(word) == 1 && word[0] >= '0' && word[0] <= '9' {
			if strings.Index(v, word) == -1 {
				return errors.New("number doesn't appear in the variable name")
			}
		} else if isImportantWordInCertificateName(word) {
			if strings.Index(v, word) == -1 {
				return errors.New(word + " doesn't appear in the variable name")
			}
		}
	}

	return nil
}

// isImportantWordInCertificateName returns true if w must be found in any
// corresponding variable name.
func isImportantWordInCertificateName(w string) bool {
	switch w {
	case "Universal", "Global", "EV", "G1", "G2", "G3", "G4", "G5":
		return true
	}
	return false
}

// checkDuplicatePins returns an error if any pins have the same name or the same hash.
func checkDuplicatePins(pins []pin) error {
	seenNames := make(map[string]bool)
	seenHashes := make(map[string]string)

	for _, pin := range pins {
		if _, ok := seenNames[pin.name]; ok {
			return fmt.Errorf("duplicate name: %s", pin.name)
		}
		seenNames[pin.name] = true

		strHash := string(pin.spkiHash)
		if otherName, ok := seenHashes[strHash]; ok {
			return fmt.Errorf("duplicate hash for %s and %s", pin.name, otherName)
		}
		seenHashes[strHash] = pin.name
	}

	return nil
}

// checkCertsInPinsets returns an error if
//   a) unknown pins are mentioned in |pinsets|
//   b) unused pins are given in |pins|
//   c) a pinset name is used twice
func checkCertsInPinsets(pinsets []pinset, pins []pin) error {
	pinNames := make(map[string]bool)
	for _, pin := range pins {
		pinNames[pin.name] = true
	}

	usedPinNames := make(map[string]bool)
	pinsetNames := make(map[string]bool)

	for _, pinset := range pinsets {
		if _, ok := pinsetNames[pinset.Name]; ok {
			return fmt.Errorf("duplicate pinset name: %s", pinset.Name)
		}
		pinsetNames[pinset.Name] = true

		var allPinNames []string
		allPinNames = append(allPinNames, pinset.Include...)
		allPinNames = append(allPinNames, pinset.Exclude...)

		for _, pinName := range allPinNames {
			if _, ok := pinNames[pinName]; !ok {
				return fmt.Errorf("unknown pin: %s", pinName)
			}
			usedPinNames[pinName] = true
		}
	}

	for pinName := range pinNames {
		if _, ok := usedPinNames[pinName]; !ok {
			return fmt.Errorf("unused pin: %s", pinName)
		}
	}

	return nil
}

func checkNoopEntries(entries []hsts) error {
	for _, e := range entries {
		if len(e.Mode) == 0 && len(e.Pins) == 0 && !e.ExpectCT {
			switch e.Name {
			// This entry is deliberately used as an exclusion.
			case "learn.doubleclick.net":
				continue
			default:
				return errors.New("Entry for " + e.Name + " has no mode and no pins and is not expect-CT")
			}
		}
	}

	return nil
}

func checkSubdomainsFlags(entries []hsts) error {
	for _, e := range entries {
		if e.SubdomainsForPinning && e.Subdomains {
			return errors.New("Entry for " + e.Name + " sets include_subdomains_for_pinning but also sets include_subdomains, which implies it")
		}
	}

	return nil
}

func checkDuplicateEntries(entries []hsts) error {
	seen := make(map[string]bool)

	for _, e := range entries {
		if _, ok := seen[e.Name]; ok {
			return errors.New("Duplicate entry for " + e.Name)
		}
		seen[e.Name] = true
	}

	return nil
}

func writeHeader(out *bufio.Writer) {
	out.WriteString(`// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is automatically generated by
// transport_security_state_static_generate.go.
// You can find it at https://github.com/chromium/hstspreload/.

#ifndef NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_
#define NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_

#include <stdint.h>

`)

}

func writeFooter(out *bufio.Writer) {
	out.WriteString("#endif  // NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_\n")
}

func writeDomainIDs(out *bufio.Writer, domainIDs []string) {
	out.WriteString("enum SecondLevelDomainName {\n")

	for _, id := range domainIDs {
		out.WriteString("  DOMAIN_" + id + ",\n")
	}

	out.WriteString(`  // Boundary value for UMA_HISTOGRAM_ENUMERATION.
  DOMAIN_NUM_EVENTS,
};

`)
}

func writeExpectCTReportURIIds(out *bufio.Writer, entries []hsts) map[string]int {
	result := make(map[string]int)
	i := 0

	out.WriteString("static const char* const kExpectCTReportURIs[] = {\n")
	for _, e := range entries {
		if e.ExpectCT {
			if _, seen := result[e.ExpectCTReportURI]; !seen {
				out.WriteString("    \"" + e.ExpectCTReportURI + "\",\n")
				result[e.ExpectCTReportURI] = i
				i = i + 1
			}
		}
	}

	out.WriteString("};\n")
	return result
}

func writeCertsOutput(out *bufio.Writer, pins []pin) {
	out.WriteString(`// These are SubjectPublicKeyInfo hashes for public key pinning. The
// hashes are SHA256 digests.

`)

	for _, pin := range pins {
		fmt.Fprintf(out, "static const char kSPKIHash_%s[] =\n", pin.name)
		var s1, s2 string
		for _, c := range pin.spkiHash[:len(pin.spkiHash)/2] {
			s1 += fmt.Sprintf("\\x%02x", c)
		}
		for _, c := range pin.spkiHash[len(pin.spkiHash)/2:] {
			s2 += fmt.Sprintf("\\x%02x", c)
		}
		fmt.Fprintf(out, "    \"%s\"\n    \"%s\";\n\n", s1, s2)
	}
}

// uppercaseFirstLetter returns s with the first letter uppercased.
func uppercaseFirstLetter(s string) string {
	// We need to find the index of the second code-point, which may not be
	// one.
	for i := range s {
		if i == 0 {
			continue
		}
		return strings.ToUpper(s[:i]) + s[i:]
	}
	return strings.ToUpper(s)
}

func writeListOfPins(w io.Writer, name string, pinNames []string) {
	fmt.Fprintf(w, "static const char* const %s[] = {\n", name)
	for _, pinName := range pinNames {
		fmt.Fprintf(w, "    kSPKIHash_%s,\n", pinName)
	}
	fmt.Fprintf(w, "    NULL,\n};\n")
}

// toDNS returns a string converts the domain name |s| into C-escaped,
// length-prefixed form and also returns the length of the interpreted string.
// i.e. for an input "example.com" it will return "\\007" "example" "\\003"
// "com", 13. The octal length bytes are in their own string because Visual
// Studio won't accept a digit after an octal escape otherwise.
func toDNS(s string) (string, int) {
	labels := strings.Split(s, ".")

	var name string
	var l int
	for i, label := range labels {
		if len(label) > 63 {
			panic("DNS label too long")
		}
		if i > 0 {
			name += " "
		}
		name += fmt.Sprintf("\"\\%03o\" ", len(label))
		name += "\"" + label + "\""
		l += len(label) + 1
	}
	l++ // For the length of the root label.

	return name, l
}

// domainConstant converts the domain name |s| into a string of the form
// "DOMAIN_" + uppercase last two labels.
func domainConstant(s string) string {
	labels := strings.Split(s, ".")
	gtld := strings.ToUpper(labels[len(labels)-1])
	if len(labels) == 1 {
		return fmt.Sprintf("DOMAIN_%s", gtld)
	}
	domain := strings.Replace(strings.ToUpper(labels[len(labels)-2]), "-", "_", -1)
	return fmt.Sprintf("DOMAIN_%s_%s", domain, gtld)
}

type pinsetData struct {
	// index contains the index of the pinset in kPinsets
	index                                      int
	acceptPinsVar, rejectPinsVar, reportURIVar string
}

func writeHSTSOutput(out *bufio.Writer, hsts preloaded, expectCTReportURIIds map[string]int) error {
	out.WriteString(`// The following is static data describing the hosts that are hardcoded with
// certificate pins or HSTS information.

// kNoRejectedPublicKeys is a placeholder for when no public keys are rejected.
static const char* const kNoRejectedPublicKeys[] = {
    NULL,
};

// kNoReportURI is a placeholder for when a pinset does not have a report URI.
static const char kNoReportURI[] = "";

`)

	// pinsets maps from a pinset string in the JSON file to an index in
	// the kPinsets array.
	pinsets := make(map[string]pinsetData)
	pinsetNum := 0

	for _, pinset := range hsts.Pinsets {
		name := uppercaseFirstLetter(pinset.Name)
		acceptableListName := fmt.Sprintf("k%sAcceptableCerts", name)
		writeListOfPins(out, acceptableListName, pinset.Include)

		rejectedListName := "kNoRejectedPublicKeys"
		if len(pinset.Exclude) > 0 {
			rejectedListName = fmt.Sprintf("k%sRejectedCerts", name)
			writeListOfPins(out, rejectedListName, pinset.Exclude)
		}

		reportURIName := "kNoReportURI"
		if reportURI := pinset.ReportURI; len(reportURI) > 0 {
			reportURIName = fmt.Sprintf("k%sReportURI", name)
			fmt.Fprintf(out, "static const char %s[] = %q;\n", reportURIName, reportURI)
		}

		pinsets[pinset.Name] = pinsetData{pinsetNum, acceptableListName, rejectedListName, reportURIName}
		pinsetNum++
	}

	out.WriteString(`
struct Pinset {
  const char* const* const accepted_pins;
  const char* const* const rejected_pins;
  const char* const report_uri;
};

static const struct Pinset kPinsets[] = {
`)

	for _, pinset := range hsts.Pinsets {
		data := pinsets[pinset.Name]
		fmt.Fprintf(out, "    {%s, %s, %s},\n", data.acceptPinsVar, data.rejectPinsVar, data.reportURIVar)
	}

	out.WriteString("};\n")

	// domainIDs maps from domainConstant(domain) to an index in kDomainIDs.
	domainIDs := make(map[string]int)
	for i, id := range hsts.DomainIDs {
		domainIDs["DOMAIN_"+id] = i
	}

	// First, create a Huffman tree using approximate weights and generate
	// the output using that. During output, the true counts for each
	// character will be collected for use in building the real Huffman
	// tree.
	root := buildHuffman(approximateHuffman(hsts.Entries))
	huffmanMap := root.toMap()

	hstsLiteralWriter := cLiteralWriter{out: ioutil.Discard}
	hstsBitWriter := trieWriter{
		w:                    &hstsLiteralWriter,
		pinsets:              pinsets,
		domainIDs:            domainIDs,
		expectCTReportURIIds: expectCTReportURIIds,
		huffman:              huffmanMap,
	}

	_, err := writeEntries(&hstsBitWriter, hsts.Entries)
	if err != nil {
		return err
	}
	hstsBitWriter.Close()
	origLength := hstsBitWriter.position

	// Now that we have the true counts for each character, build the true
	// Huffman tree.
	root = buildHuffman(hstsBitWriter.huffmanCounts)
	huffmanMap = root.toMap()

	out.WriteString(`
// kHSTSHuffmanTree describes a Huffman tree. The nodes of the tree are pairs
// of uint8s. The last node in the array is the root of the tree. Each pair is
// two uint8_t values, the first is "left" and the second is "right". If a
// uint8_t value has the MSB set then it represents a literal leaf value.
// Otherwise it's a pointer to the n'th element of the array.
static const uint8_t kHSTSHuffmanTree[] = {
`)

	huffmanLiteralWriter := cLiteralWriter{out: out}
	root.WriteTo(&huffmanLiteralWriter)

	out.WriteString(`
};

static const uint8_t kPreloadedHSTSData[] = {
`)

	hstsLiteralWriter = cLiteralWriter{out: out}
	hstsBitWriter = trieWriter{
		w:                    &hstsLiteralWriter,
		pinsets:              pinsets,
		domainIDs:            domainIDs,
		expectCTReportURIIds: expectCTReportURIIds,
		huffman:              huffmanMap,
	}

	rootPosition, err := writeEntries(&hstsBitWriter, hsts.Entries)
	if err != nil {
		return err
	}
	hstsBitWriter.Close()

	bitLength := hstsBitWriter.position
	if debugging {
		fmt.Fprintf(os.Stderr, "Saved %d bits by using accurate Huffman counts.\n", origLength-bitLength)
	}
	out.WriteString(`
};

`)
	fmt.Fprintf(out, "static const unsigned kPreloadedHSTSBits = %d;\n\n", bitLength)
	fmt.Fprintf(out, "static const unsigned kHSTSRootPosition = %d;\n\n", rootPosition)

	return nil
}

// cLiteralWriter is an io.Writer that formats data suitable as the contents of
// a uint8_t array literal in C.
type cLiteralWriter struct {
	out           io.Writer
	bytesThisLine int
	count         int
}

func (clw *cLiteralWriter) WriteByte(b byte) (err error) {
	if clw.bytesThisLine == 12 {
		if _, err = clw.out.Write([]byte{'\n'}); err != nil {
			return
		}
		clw.bytesThisLine = 0
	}

	if clw.bytesThisLine == 0 {
		if _, err = clw.out.Write([]byte("    ")); err != nil {
			return
		}
	} else {
		if _, err = clw.out.Write([]byte{' '}); err != nil {
			return
		}
	}

	if _, err = fmt.Fprintf(clw.out, "0x%02x,", b); err != nil {
		return
	}
	clw.bytesThisLine++
	clw.count++

	return
}

// trieWriter handles wraps an io.Writer and provides a bit writing interface.
// It also contains the other information needed for writing out a compressed
// trie.
type trieWriter struct {
	w                    io.ByteWriter
	pinsets              map[string]pinsetData
	domainIDs            map[string]int
	expectCTReportURIIds map[string]int
	huffman              map[rune]bitsAndLen
	b                    byte
	used                 uint
	position             int
	huffmanCounts        [129]int
}

func (w *trieWriter) WriteBits(bits, numBits uint) error {
	for i := uint(1); i <= numBits; i++ {
		bit := byte(1 & (bits >> (numBits - i)))
		w.b |= bit << (7 - w.used)
		w.used++
		w.position++
		if w.used == 8 {
			if err := w.w.WriteByte(w.b); err != nil {
				return err
			}
			w.used = 0
			w.b = 0
		}
	}

	return nil
}

func (w *trieWriter) Close() error {
	return w.w.WriteByte(w.b)
}

// bitsOrPosition contains either some bits (if numBits > 0) or a byte offset
// in the output (otherwise).
type bitsOrPosition struct {
	bits     byte
	numBits  uint
	position int
}

// bitBuffer buffers up a series of bits and positions because the final output
// location of the data isn't known yet and so the deltas from the current
// position to the written positions isn't known yet.
type bitBuffer struct {
	b        byte
	used     uint
	elements []bitsOrPosition
}

func (buf *bitBuffer) WriteBit(bit uint) {
	buf.b |= byte(bit) << (7 - buf.used)
	buf.used++
	if buf.used == 8 {
		buf.elements = append(buf.elements, bitsOrPosition{buf.b, buf.used, 0})
		buf.used = 0
		buf.b = 0
	}
}

func (buf *bitBuffer) WriteBits(bits, numBits uint) {
	for i := uint(1); i <= numBits; i++ {
		bit := 1 & (bits >> (numBits - i))
		buf.WriteBit(bit)
	}
}

func (buf *bitBuffer) WritePosition(lastPosition *int, position int) {
	if *lastPosition != -1 {
		delta := position - *lastPosition
		if delta <= 0 {
			panic("delta position is not positive")
		}
		numBits := bitLength(delta)
		if numBits > 7+15 {
			panic("positive position delta too large")
		}
		if numBits <= 7 {
			buf.WriteBits(0, 1)
			buf.WriteBits(uint(delta), 7)
		} else {
			buf.WriteBits(1, 1)
			buf.WriteBits(numBits-8, 4)
			buf.WriteBits(uint(delta), numBits)
		}
		*lastPosition = position
		return
	}

	if buf.used != 0 {
		buf.elements = append(buf.elements, bitsOrPosition{buf.b, buf.used, 0})
		buf.used = 0
		buf.b = 0
	}

	buf.elements = append(buf.elements, bitsOrPosition{0, 0, position})
	*lastPosition = position
}

func (buf *bitBuffer) WriteChar(b byte, w *trieWriter) {
	bits, ok := w.huffman[rune(b)]
	if !ok {
		panic("WriteChar given rune not in Huffman table")
	}
	w.huffmanCounts[rune(b)]++
	buf.WriteBits(bits.bits, bits.numBits)
}

func bitLength(i int) uint {
	numBits := uint(0)
	for i != 0 {
		numBits++
		i >>= 1
	}
	return numBits
}

func (buf *bitBuffer) WriteTo(w *trieWriter) (position int, err error) {
	position = w.position

	if buf.used != 0 {
		buf.elements = append(buf.elements, bitsOrPosition{buf.b, buf.used, 0})
		buf.used = 0
		buf.b = 0
	}

	for _, elem := range buf.elements {
		if elem.numBits != 0 {
			if err := w.WriteBits(uint(elem.bits)>>(8-elem.numBits), elem.numBits); err != nil {
				return -1, err
			}
		} else {
			current := position
			target := elem.position
			if target >= current {
				panic("reference is not backwards")
			}
			delta := current - target

			numBits := bitLength(delta)

			if numBits >= 32 {
				panic("delta is too large")
			}
			w.WriteBits(uint(numBits), 5)
			w.WriteBits(uint(delta), numBits)
		}
	}

	return
}

type reversedEntry struct {
	bytes []byte
	hsts  *hsts
}

type reversedEntries []reversedEntry

func (ents reversedEntries) Len() int {
	return len(ents)
}

func (ents reversedEntries) Less(i, j int) bool {
	return bytes.Compare(ents[i].bytes, ents[j].bytes) < 0
}

func (ents reversedEntries) Swap(i, j int) {
	ents[i], ents[j] = ents[j], ents[i]
}

func (ents reversedEntries) LongestCommonPrefix() []byte {
	if len(ents) == 0 {
		return nil
	}

	var prefix []byte
	for i := 0; ; i++ {
		if i > len(ents[0].bytes) {
			break
		}
		candidate := ents[0].bytes[i]
		if candidate == terminalValue {
			break
		}
		ok := true

		for _, ent := range ents[1:] {
			if i > len(ent.bytes) || ent.bytes[i] != candidate {
				ok = false
				break
			}
		}

		if !ok {
			break
		}

		prefix = append(prefix, candidate)
	}

	return prefix
}

func (ents reversedEntries) RemovePrefix(n int) {
	for i := range ents {
		ents[i].bytes = ents[i].bytes[n:]
	}
}

func reverseName(name string) []byte {
	reversed := make([]byte, len(name)+1)

	i := 1
	for _, r := range name {
		if r == 0 || r >= 127 {
			panic("byte in name is out of range.")
		}
		reversed[len(name)-i] = byte(r)
		i++
	}
	reversed[len(reversed)-1] = terminalValue
	return reversed
}

func writeEntries(w *trieWriter, hstsEntries []hsts) (positin int, err error) {
	ents := reversedEntries(make([]reversedEntry, len(hstsEntries)))

	for i := range hstsEntries {
		ents[i].hsts = &hstsEntries[i]
		ents[i].bytes = reverseName(hstsEntries[i].Name)
	}

	sort.Stable(ents)

	return writeDispatchTables(w, ents, 0)
}

const debugging = false

func writeDispatchTables(w *trieWriter, ents reversedEntries, depth int) (position int, err error) {
	var buf bitBuffer

	if len(ents) == 0 {
		panic("empty ents passed to writeDispatchTables")
	}

	prefix := ents.LongestCommonPrefix()
	l := len(prefix)
	for l > 0 {
		buf.WriteBit(1)
		l--
	}
	buf.WriteBit(0)

	if len(prefix) > 0 {
		if debugging {
			for i := 0; i < depth; i++ {
				fmt.Printf(" ")
			}
		}
		for _, b := range prefix {
			buf.WriteChar(b, w)
			if debugging {
				fmt.Printf("%c", b)
			}
			depth++
		}
		if debugging {
			fmt.Printf("\n")
		}
	}

	ents.RemovePrefix(len(prefix))
	lastPosition := -1

	for len(ents) > 0 {
		var subents reversedEntries
		b := ents[0].bytes[0]
		var j int

		for j = 1; j < len(ents); j++ {
			if ents[j].bytes[0] != b {
				break
			}
		}

		subents = ents[:j]
		buf.WriteChar(b, w)

		if debugging {
			for i := 0; i < depth; i++ {
				fmt.Printf(" ")
			}
			fmt.Printf("?%c\n", b)
		}

		if b == terminalValue {
			if len(subents) != 1 {
				panic("multiple values with the same name")
			}
			hsts := ents[0].hsts

			includeSubdomains := uint(0)
			if hsts.Subdomains {
				includeSubdomains = 1
			}
			buf.WriteBit(includeSubdomains)

			forceHTTPS := uint(0)
			if hsts.Mode == "force-https" {
				forceHTTPS = 1
			}
			buf.WriteBit(forceHTTPS)

			if hsts.Pins == "" {
				buf.WriteBit(0)
			} else {
				buf.WriteBit(1)
				pinsID := uint(w.pinsets[hsts.Pins].index)
				if pinsID >= 16 {
					panic("too many pinsets")
				}
				buf.WriteBits(pinsID, 4)

				domainID, included := w.domainIDs[domainConstant(hsts.Name)]
				if !included {
					panic("missing domain ID for " + hsts.Name)
				}
				if domainID >= 512 {
					println(domainID)
					panic("too many domain ids")
				}
				buf.WriteBits(uint(domainID), 9)
				if !hsts.Subdomains {
					includeSubdomainsForPinning := uint(0)
					if hsts.SubdomainsForPinning {
						includeSubdomainsForPinning = 1
					}
					buf.WriteBit(includeSubdomainsForPinning)
				}
			}

			if hsts.ExpectCT {
				buf.WriteBit(1)
				expectCTReportURIId, included := w.expectCTReportURIIds[hsts.ExpectCTReportURI]
				if !included {
					panic("missing expect-CT report URI ID for " + hsts.Name)
				}
				if expectCTReportURIId >= 16 {
					panic("too many expect-CT report URIs")
				}
				buf.WriteBits(uint(expectCTReportURIId), 4)
			} else {
				buf.WriteBit(0)
			}
		} else {
			subents.RemovePrefix(1)
			pos, err := writeDispatchTables(w, subents, depth+2)
			if err != nil {
				return -1, err
			}
			if debugging {
				for i := 0; i < depth; i++ {
					fmt.Printf(" ")
				}
				fmt.Printf("@%d\n", pos)
			}
			buf.WritePosition(&lastPosition, pos)
		}

		ents = ents[j:]
	}

	buf.WriteChar(endOfTableValue, w)

	position = w.position
	buf.WriteTo(w)
	return
}

type bitsAndLen struct {
	bits    uint
	numBits uint
}

// huffmanNode represents a node in a Huffman tree, where count is the
// frequency of the value that the node represents and is used only in tree
// construction.
type huffmanNode struct {
	value rune
	count int
	left  *huffmanNode
	right *huffmanNode
}

func (n *huffmanNode) isLeaf() bool {
	return n.left == nil && n.right == nil
}

// toMap converts the Huffman tree rooted at n into a map from value to the bit
// sequence for that value.
func (n *huffmanNode) toMap() map[rune]bitsAndLen {
	ret := make(map[rune]bitsAndLen)
	n.fillMap(ret, 0, 0)
	return ret
}

// fillMap is a helper function for toMap that recurses down the Huffman tree
// and fills in entries in m.
func (n *huffmanNode) fillMap(m map[rune]bitsAndLen, bits, numBits uint) {
	if n.isLeaf() {
		m[n.value] = bitsAndLen{bits, numBits}
	} else {
		newBits := bits << 1
		n.left.fillMap(m, newBits, numBits+1)
		n.right.fillMap(m, newBits|1, numBits+1)
	}
}

// WriteTo serialises the Huffman tree rooted at n to w in a format that can be
// processed by the Chromium code. See the comments in Chromium about the
// format.
func (n *huffmanNode) WriteTo(w *cLiteralWriter) (position int, err error) {
	var leftValue, rightValue uint8
	var childPosition int

	if n.left.isLeaf() {
		leftValue = 128 | byte(n.left.value)
	} else {
		if childPosition, err = n.left.WriteTo(w); err != nil {
			return
		}
		if childPosition >= 512 {
			panic("huffman tree too large")
		}
		leftValue = byte(childPosition / 2)
	}

	if n.right.isLeaf() {
		rightValue = 128 | byte(n.right.value)
	} else {
		if childPosition, err = n.right.WriteTo(w); err != nil {
			return
		}
		if childPosition >= 512 {
			panic("huffman tree too large")
		}
		rightValue = byte(childPosition / 2)
	}

	position = w.count
	if err = w.WriteByte(leftValue); err != nil {
		return
	}
	if err = w.WriteByte(rightValue); err != nil {
		return
	}
	return
}

type nodeList []*huffmanNode

func (l nodeList) Len() int {
	return len(l)
}

func (l nodeList) Less(i, j int) bool {
	if l[i].count != l[j].count {
		return l[i].count < l[j].count
	}
	return l[i].value < l[j].value
}

func (l nodeList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// terminalValue indicates the end of a string (which is the beginning of the
// string since we process it backwards).
const terminalValue = 0

// endOfTableValue is a sentinel value that indicates that there are no more
// entries in a dispatch table.
const endOfTableValue = 127

// approximateHuffman calculates an approximate frequency table for entries,
// for use in building a Huffman tree.
func approximateHuffman(entries []hsts) (useCounts [129]int) {
	for _, ent := range entries {
		for _, r := range ent.Name {
			if r == 0 || r >= 127 {
				panic("Rune out of range in name")
			}
			useCounts[r]++
		}
		useCounts[terminalValue]++
		useCounts[endOfTableValue]++
	}

	return
}

// buildHuffman builds a Huffman tree using useCounts as a frequency table.
func buildHuffman(useCounts [129]int) (root *huffmanNode) {
	numNonZero := 0
	for _, count := range useCounts {
		if count != 0 {
			numNonZero++
		}
	}

	nodes := nodeList(make([]*huffmanNode, 0, numNonZero))
	for char, count := range useCounts {
		if count != 0 {
			nodes = append(nodes, &huffmanNode{rune(char), count, nil, nil})
		}
	}

	if len(nodes) < 2 {
		panic("cannot build a tree with a single node")
	}

	sort.Stable(nodes)

	for len(nodes) > 1 {
		parent := &huffmanNode{0, nodes[0].count + nodes[1].count, nodes[0], nodes[1]}
		nodes = nodes[1:]
		nodes[0] = parent

		sort.Stable(nodes)
	}

	return nodes[0]
}
