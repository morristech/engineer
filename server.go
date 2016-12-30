package engineer

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func Listen(addr string) (net.Listener, error) {
	listener, err := ListenReusable("tcp", addr)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func ListenTLS(cert, key, addr string) (net.Listener, error) {
	listener, err := ListenReusable("tcp", addr)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, err
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

	return tls.NewListener(listener, tlsConfig), nil
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
