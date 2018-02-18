package engineer

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func NewServer(addr string) (*http.Server, net.Listener, error) {
	server := &http.Server{ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	listener, err := ListenReusable("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return server, listener, nil
}

func NewServerTLS(addr, cert, key string) (*http.Server, net.Listener, error) {
	certificate, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, nil, err
	}

	// https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
	config := &tls.Config{
		// no need to have http/2 yet, not sure what it would offer for current use case
		// NextProtos:   []string{"h2", "http/1.1"},
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{certificate},
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	server, listener, err := NewServer(addr)
	if err != nil {
		return nil, nil, err
	}
	listener = tls.NewListener(listener, config)
	return server, listener, nil
}

func ServeUntilTerminate(server *http.Server, listener net.Listener) error {
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)

	serverError := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil {
			serverError <- err
		}
	}()

	select {
	case <-sigterm:
		// on SIGTERM, close the listener
		// disable keep alives so that new requests cannot be made after listeners are closed
		// maybe checkout https://beta.golang.org/doc/go1.8#http_shutdown
		server.SetKeepAlivesEnabled(false)
		// closing the listener will cause a server error, but we're going to return right now so we'll never see it
		listener.Close()
		return nil
	case err := <-serverError:
		return err
	}
}
