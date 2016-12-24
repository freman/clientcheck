package main

import (
	"crypto/tls"
	"net"
)

type listener struct {
	net.Listener
	config *tls.Config
}

type wrappedConnetion struct {
	net.Conn
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Clone the tls.Config structure replacing the GetCertificate function with our own hook
	config := &tls.Config{
		Rand:                        l.config.Rand,
		Time:                        l.config.Time,
		Certificates:                l.config.Certificates,
		NameToCertificate:           l.config.NameToCertificate,
		RootCAs:                     l.config.RootCAs,
		NextProtos:                  l.config.NextProtos,
		ServerName:                  l.config.ServerName,
		ClientAuth:                  l.config.ClientAuth,
		ClientCAs:                   l.config.ClientCAs,
		InsecureSkipVerify:          l.config.InsecureSkipVerify,
		CipherSuites:                l.config.CipherSuites,
		PreferServerCipherSuites:    l.config.PreferServerCipherSuites,
		SessionTicketsDisabled:      l.config.SessionTicketsDisabled,
		SessionTicketKey:            l.config.SessionTicketKey,
		ClientSessionCache:          l.config.ClientSessionCache,
		MinVersion:                  l.config.MinVersion,
		MaxVersion:                  l.config.MaxVersion,
		CurvePreferences:            l.config.CurvePreferences,
		DynamicRecordSizingDisabled: l.config.DynamicRecordSizingDisabled,
		Renegotiation:               l.config.Renegotiation,
	}
	config.GetCertificate = getCertificateHook(c.RemoteAddr().String(), config, l.config.GetCertificate)

	return tls.Server(c, config), nil
}
