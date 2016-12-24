package main

type keyPair struct {
	CertFile string
	KeyFile  string
}

type acmeConfig struct {
	DirCache      string
	HostWhitelist []string
	Email         string
}

var config = struct {
	Listen       string
	UseACME      bool
	ACME         acmeConfig
	Certificates []keyPair
}{
	Listen: ":443",
	ACME: acmeConfig{
		DirCache:      "/tmp",
		HostWhitelist: []string{"example.com"},
		Email:         "example@example.com",
	},
	Certificates: []keyPair{},
}
