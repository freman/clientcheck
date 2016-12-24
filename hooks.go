package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/orcaman/concurrent-map"
)

var tlsInfoStash = cmap.New()

func connStateHook(c net.Conn, state http.ConnState) {
	if state == http.StateClosed {
		remoteAddr := c.RemoteAddr().String()
		tlsInfoStash.Remove(remoteAddr)
	}
}

func getCertificateHook(remoteAddr string, c *tls.Config, chain func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
		o := &clientInfo{InsecureSuites: make(map[string][]string)}
		for _, suite := range helloInfo.CipherSuites {
			if v, exists := cipherSuiteMap[suite]; exists {
				o.SupportedSuites = append(o.SupportedSuites, v)
				if strings.Contains(v, "DHE_") {
					o.EphemeralKeysSupported = true
				}

				if strings.Contains(v, "_CBC_") {
					// Set to false later if tls <= 1.0
					o.HasBeastVulnSuites = true
				}

				if fewBitCipherSuites[v] {
					o.InsecureSuites[v] = append(o.InsecureSuites[v], fewBitReason)
				}
				if nullCipherSuites[v] {
					o.InsecureSuites[v] = append(o.InsecureSuites[v], nullReason)
				}
				if nullAuthCipherSuites[v] {
					o.InsecureSuites[v] = append(o.InsecureSuites[v], nullAuthReason)
				}
				if rc4CipherSuites[v] {
					o.InsecureSuites[v] = append(o.InsecureSuites[v], rc4Reason)
				}

			} else {
				s := ""
				if w, found := weirdNSSSuites[suite]; found {
					o.InsecureSuites[w] = append(o.InsecureSuites[w], weirdNSSReason)
					s = w
				} else {
					o.UnknownSupportedSuites = true
					s = fmt.Sprintf("Unknown(0x%x)", suite)
				}
				o.SupportedSuites = append(o.SupportedSuites, s)
			}
		}

		for _, curve := range helloInfo.SupportedCurves {
			if v, exists := curveMap[curve]; exists {
				o.SupportedCurves = append(o.SupportedCurves, v)
			} else {
				o.SupportedCurves = append(o.SupportedCurves, fmt.Sprintf("Unknown(0x%x)", curve))
			}
		}
		for _, point := range helloInfo.SupportedPoints {
			o.SupportedPoints = append(o.SupportedPoints, fmt.Sprintf("0x%x", point))
		}

		tlsInfoStash.Set(remoteAddr, o)

		if chain == nil {
			return getCertificateFallback(c, helloInfo)
		}
		return chain(helloInfo)
	}
}
