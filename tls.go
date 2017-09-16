package hstspreload

import (
	"crypto/tls"
	"crypto/x509"
)

func checkChain(connState tls.ConnectionState) Issues {
	fullChain := connState.VerifiedChains[0]
	chain := fullChain[:len(fullChain)-1] // Ignore the root CA
	return checkSHA1(chain)
}

func checkSHA1(chain []*x509.Certificate) Issues {
	issues := Issues{}

	for _, cert := range chain {
		if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			return issues.addErrorf(
				IssueCode("domain.tls.sha1"),
				"SHA-1 Certificate",
				"One or more of the certificates in your certificate chain "+
					"is signed using SHA-1. This needs to be replaced. "+
					"See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. "+
					"(The first SHA-1 certificate found has a common-name of %q.)",
				cert.Subject.CommonName,
			)
		}
	}

	return issues
}

func checkCipherSuite(connState tls.ConnectionState) Issues {
	issues := Issues{}

	// No need to check the TLS version, since the modern ciphers are only supported on TLS 1.2

	switch connState.CipherSuite {
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		fallthrough
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		fallthrough
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		fallthrough
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		fallthrough
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		fallthrough
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return Issues{}
	default:
		return issues.addWarningf(
			IssueCode("tls.obsolete_cipher_suite"),
			"Obsolete Cipher Suite",
			"The site is using obsolete TLS settings. "+
				"Check out the site at https://www.ssllabs.com/ssltest/analyze.html?d=%s",
			domain,
		)
	}
}
