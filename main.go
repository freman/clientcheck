package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
)

func checkHandler(w http.ResponseWriter, r *http.Request) {
	i, found := tlsInfoStash.Get(r.RemoteAddr)
	var o *clientInfo
	if found {
		o = i.(*clientInfo).ImportRequest(r)
	}

	js, err := json.Marshal(o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Date", time.Now().Format(http.TimeFormat))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func main() {
	fConfig := flag.String("config", "config.toml", "Path to configuration")
	flag.Parse()

	_, err := toml.DecodeFile(*fConfig, &config)
	if err != nil {
		log.WithError(err).Fatal("Unable to parse the configuration file")
	}

	http.HandleFunc("/", checkHandler)

	tlsConfig := &tls.Config{
		NextProtos:               []string{"h2", "http/1.1"},
		MinVersion:               tls.VersionSSL30,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}

	if config.UseACME {
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(config.ACME.HostWhitelist...),
			Email:      config.ACME.Email,
			Cache:      autocert.DirCache(config.ACME.DirCache),
		}
		tlsConfig.GetCertificate = m.GetCertificate
	} else {
		certCount := len(config.Certificates)
		if certCount == 0 {
			log.Fatal("At least one certificate required")
		}
		tlsConfig.Certificates = make([]tls.Certificate, certCount)
		var err error
		for i := range tlsConfig.Certificates {
			tlsConfig.Certificates[i], err = tls.LoadX509KeyPair(config.Certificates[i].CertFile, config.Certificates[i].KeyFile)
			if err != nil {
				log.WithError(err).Fatal("Unable to load given certificates")
			}
		}
		tlsConfig.BuildNameToCertificate()
	}

	s := &http.Server{
		TLSConfig: tlsConfig,
		ConnState: connStateHook,
	}

	l, err := net.Listen("tcp", config.Listen)
	if err != nil {
		log.WithError(err).Fatal("Unable to listen")
	}

	tl := &listener{
		Listener: l,
		config:   tlsConfig,
	}

	log.Infof("Listening for HTTPS traffic on %s", config.Listen)

	s.Serve(tl)

}
