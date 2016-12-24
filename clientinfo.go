package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

type clientInfo struct {
	*tls.ConnectionState
	Version      string
	CipherSuite  string
	Headers      http.Header
	RemoteAddr   string
	HTTPProtocol string

	EphemeralKeysSupported bool

	SupportedSuites        []string
	SupportedCurves        []string
	SupportedPoints        []string
	InsecureSuites         map[string][]string
	UnknownSupportedSuites bool
	HasBeastVulnSuites     bool
}

func (c *clientInfo) ImportConnectionState(state *tls.ConnectionState) *clientInfo {
	c.ConnectionState = state

	switch state.Version {
	case tls.VersionSSL30:
		c.Version = "SSL 3.0"
	case tls.VersionTLS10:
		c.Version = "TLS 1.0"
	case tls.VersionTLS11:
		c.Version = "TLS 1.1"
	case tls.VersionTLS12:
		c.Version = "TLS 1.2"
	default:
		c.Version = "Unknown"
	}

	c.HasBeastVulnSuites = c.HasBeastVulnSuites && state.Version <= tls.VersionTLS10

	var ok bool
	if c.CipherSuite, ok = cipherSuiteMap[state.CipherSuite]; !ok {
		c.CipherSuite = fmt.Sprintf("Unknown 0x%X", state.CipherSuite)
	}

	return c
}

func (c *clientInfo) ImportRequest(r *http.Request) *clientInfo {
	c.ImportConnectionState(r.TLS)
	c.Headers = r.Header
	c.RemoteAddr = r.RemoteAddr
	c.HTTPProtocol = r.Proto

	return c
}
