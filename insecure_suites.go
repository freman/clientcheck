// The MIT License (MIT)
//
// Copyright (c) 2013 Jeffrey M Hodges
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// This file originally sourced from https://github.com/jmhodges/howsmyssl

package main

var (
	fewBitReason   = "uses keys smaller than 128 bits in its encryption"
	nullReason     = "specifies no encryption at all for the connection"
	nullAuthReason = "is open to man-in-the-middle attacks because it does not authenticate the server"
	weirdNSSReason = "was meant to die with SSL 3.0 and is of unknown safety"
	rc4Reason      = "uses RC4 which has insecure biases in its output"
)

// Cipher suites with less than 128-bit encryption.
// Generated with (on an OpenSSL build newer than 1.0.1e with the enable-ssl-trace option):
//   ./openssl ciphers -v -stdname LOW:EXPORT | awk '{ print "\""$1"\": true," }' | grep -v UNKNOWN | sed 's/SSL/TLS/' | sort
//
// plus the manual addition of:
//   TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5	 40-bit encryption, export grade
//   TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA	 40-bit encryption, export grade
//   TLS_KRB5_EXPORT_WITH_RC4_40_MD5	     40-bit encryption, export grade
//   TLS_KRB5_EXPORT_WITH_RC4_40_SHA	     40-bit encryption, export grade
//   TLS_KRB5_WITH_DES_CBC_MD5	             56-bit encryption
//   TLS_KRB5_WITH_DES_CBC_SHA               56-bit encryption
//
// and, from https://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01:
//
//   TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA     56-bit encryption, export grade
//   TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA 56-bit encryption, export grade
//   TLS_RSA_EXPORT1024_WITH_RC4_56_SHA      56-bit encryption, export grade
//   TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA  56-bit encryption, export grade
//
// Plus a few more found in https://github.com/jmhodges/howsmyssl/issues/56:
//
//   TLS_RSA_EXPORT1024_WITH_RC4_56_MD5      56-bit encryption, export grade
//   TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5  56-bit encryption, export grade
//
var fewBitCipherSuites = map[string]bool{
	"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA":   true,
	"TLS_DHE_DSS_WITH_DES_CBC_SHA":            true,
	"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA":   true,
	"TLS_DHE_RSA_WITH_DES_CBC_SHA":            true,
	"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA":    true,
	"TLS_DH_DSS_WITH_DES_CBC_SHA":             true,
	"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA":    true,
	"TLS_DH_RSA_WITH_DES_CBC_SHA":             true,
	"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA":   true,
	"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":      true,
	"TLS_DH_anon_WITH_DES_CBC_SHA":            true,
	"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":       true,
	"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5":      true,
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":          true,
	"TLS_RSA_WITH_DES_CBC_SHA":                true,
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5":     true,
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA":     true,
	"TLS_KRB5_EXPORT_WITH_RC4_40_MD5":         true,
	"TLS_KRB5_EXPORT_WITH_RC4_40_SHA":         true,
	"TLS_KRB5_WITH_DES_CBC_MD5":               true,
	"TLS_KRB5_WITH_DES_CBC_SHA":               true,
	"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA":     true,
	"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA": true,
	"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA":      true,
	"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA":  true,
	"TLS_RSA_EXPORT1024_WITH_RC4_56_MD5":      true,
	"TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5":  true,
}

// Cipher suites that offer no encryption.
// Generated with:
//   grep NULL all_suites.go
//
// A smaller subset can be found with (on an OpenSSL build newer than 1.0.1e
// with the enable-ssl-trace option):
//   ./openssl ciphers -v -stdname NULL | awk '{ print "\""$1"\": true," }' | sed 's/SSL/TLS/' | sort
var nullCipherSuites = map[string]bool{
	"TLS_DHE_PSK_WITH_NULL_SHA":      true,
	"TLS_DHE_PSK_WITH_NULL_SHA256":   true,
	"TLS_DHE_PSK_WITH_NULL_SHA384":   true,
	"TLS_ECDHE_ECDSA_WITH_NULL_SHA":  true,
	"TLS_ECDHE_PSK_WITH_NULL_SHA":    true,
	"TLS_ECDHE_PSK_WITH_NULL_SHA256": true,
	"TLS_ECDHE_PSK_WITH_NULL_SHA384": true,
	"TLS_ECDHE_RSA_WITH_NULL_SHA":    true,
	"TLS_ECDH_ECDSA_WITH_NULL_SHA":   true,
	"TLS_ECDH_RSA_WITH_NULL_SHA":     true,
	"TLS_ECDH_anon_WITH_NULL_SHA":    true,
	"TLS_NULL_WITH_NULL_NULL":        true,
	"TLS_PSK_WITH_NULL_SHA":          true,
	"TLS_PSK_WITH_NULL_SHA256":       true,
	"TLS_PSK_WITH_NULL_SHA384":       true,
	"TLS_RSA_PSK_WITH_NULL_SHA":      true,
	"TLS_RSA_PSK_WITH_NULL_SHA256":   true,
	"TLS_RSA_PSK_WITH_NULL_SHA384":   true,
	"TLS_RSA_WITH_NULL_MD5":          true,
	"TLS_RSA_WITH_NULL_SHA":          true,
	"TLS_RSA_WITH_NULL_SHA256":       true,
}

// Cipher suites that offer encryption, but no authentication, opening them up
// to MITM attacks.
//
// Generated by combining
//   grep anon all_suites.go | awk '{ print $2 }' | sed 's/,/: true,/' | sort
var nullAuthCipherSuites = map[string]bool{
	"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA":    true,
	"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":       true,
	"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA":        true,
	"TLS_DH_anon_WITH_AES_128_CBC_SHA":         true,
	"TLS_DH_anon_WITH_AES_128_CBC_SHA256":      true,
	"TLS_DH_anon_WITH_AES_128_GCM_SHA256":      true,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA":         true,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA256":      true,
	"TLS_DH_anon_WITH_AES_256_GCM_SHA384":      true,
	"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256":     true,
	"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256":     true,
	"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384":     true,
	"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384":     true,
	"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA":    true,
	"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256": true,
	"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256": true,
	"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA":    true,
	"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256": true,
	"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384": true,
	"TLS_DH_anon_WITH_DES_CBC_SHA":             true,
	"TLS_DH_anon_WITH_RC4_128_MD5":             true,
	"TLS_DH_anon_WITH_SEED_CBC_SHA":            true,
	"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA":      true,
	"TLS_ECDH_anon_WITH_AES_128_CBC_SHA":       true,
	"TLS_ECDH_anon_WITH_AES_256_CBC_SHA":       true,
	"TLS_ECDH_anon_WITH_NULL_SHA":              true,
	"TLS_ECDH_anon_WITH_RC4_128_SHA":           true,
}

// Cipher suites that use RC4 which has biases in its output, and has
// been marked as insecure by the IETF. See https://tools.ietf.org/html/rfc7465
//
// Generated with:
//   grep RC4 all_suites.go
//
// and confirmed against
// https://tools.ietf.org/html/rfc7465#appendix-A which is missing 4
// cipher suites included here.
var rc4CipherSuites = map[string]bool{
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":         true,
	"TLS_RSA_WITH_RC4_128_MD5":               true,
	"TLS_RSA_WITH_RC4_128_SHA":               true,
	"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":     true,
	"TLS_DH_anon_WITH_RC4_128_MD5":           true,
	"TLS_KRB5_WITH_RC4_128_SHA":              true,
	"TLS_KRB5_WITH_RC4_128_MD5":              true,
	"TLS_KRB5_EXPORT_WITH_RC4_40_SHA":        true,
	"TLS_KRB5_EXPORT_WITH_RC4_40_MD5":        true,
	"TLS_PSK_WITH_RC4_128_SHA":               true,
	"TLS_DHE_PSK_WITH_RC4_128_SHA":           true,
	"TLS_RSA_PSK_WITH_RC4_128_SHA":           true,
	"TLS_ECDH_ECDSA_WITH_RC4_128_SHA":        true,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":       true,
	"TLS_ECDH_RSA_WITH_RC4_128_SHA":          true,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":         true,
	"TLS_ECDH_anon_WITH_RC4_128_SHA":         true,
	"TLS_ECDHE_PSK_WITH_RC4_128_SHA":         true,
	"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA":     true,
	"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA": true,
	"TLS_DHE_DSS_WITH_RC4_128_SHA":           true,
}

// Obsolete cipher suites in NSS that were meant to die with SSL 3.0 but
// 0xFEFF is still emitted by Firefox 25.0. Discussed here:
// https://groups.google.com/forum/#!topic/mozilla.dev.tech.crypto/oWk0FkKsek4
// and
// http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
var weirdNSSSuites = map[uint16]string{
	0xFEFE: "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
	0xFEFF: "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
}
