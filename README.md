# HSTS Preload List – Utility Code

[![GoDoc](https://godoc.org/github.com/chromium/hstspreload?status.svg)](https://godoc.org/github.com/chromium/hstspreload)
[![Build Status](https://travis-ci.org/chromium/hstspreload.svg?branch=master)](https://travis-ci.org/chromium/hstspreload)

HSTS is [HTTP Strict Transport Security](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security), which is a policy system for web sites to express a desire only to be contacted over HTTPS.

See <https://github.com/chromium/hstspreload.org> for the submission site code.

## Usage

To check if a domain satisfies the requirements for preloading (assuming `$PATH` contains `$GOPATH/bin/`):

    go get github.com/chromium/hstspreload/...
    hstspreload preloadabledomain wikipedia.org

For full documentation, see <https://godoc.org/github.com/chromium/hstspreload>
