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

func ListenAndServe(addr string, handler http.Handler) error {
	listener, err := ListenReusable("tcp", addr)
	if err != nil {
		return err
	}

	return serveUntilTerminate(listener, handler)
}

func ListenAndServeTLS(addr string, cert, key string, handler http.Handler) error {
	listener, err := ListenReusable("tcp", addr)
	if err != nil {
		return err
	}

	certificate, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{certificate},
		// based on https://github.com/cloudflare/sslconfig/blob/master/conf
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS10,
	}

	return serveUntilTerminate(tls.NewListener(listener, tlsConfig), handler)
}

func serveUntilTerminate(listener net.Listener, handler http.Handler) error {
	// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	// writeTimeout is different with HTTPS so use 60 seconds instead of 30
	server := &http.Server{Handler: handler, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}

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
		server.SetKeepAlivesEnabled(false)
		// closing the listener will cause a server error
		listener.Close()
		return nil
	case err := <-serverError:
		return err
	}
}
