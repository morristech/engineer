package engineer

import (
	"net"
	"os"
	"syscall"
	"time"
)

// based on https://raw.githubusercontent.com/kavu/go_reuseport/master/reuseport.go

func ListenReusable(network, laddr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr(network, laddr)
	if err != nil {
		return nil, err
	}

	sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(sockfd, syscall.SOL_SOCKET, SO_REUSEPORT, 1); err != nil {
		return nil, err
	}

	addr := [4]byte{}
	if tcpAddr.IP != nil {
		copy(addr[:], tcpAddr.IP[12:])
	}
	if err := syscall.Bind(sockfd, &syscall.SockaddrInet4{Port: tcpAddr.Port, Addr: addr}); err != nil {
		return nil, err
	}

	if err := syscall.Listen(sockfd, syscall.SOMAXCONN); err != nil {
		return nil, err
	}

	sockFile := os.NewFile(uintptr(sockfd), "")

	fileListener, err := net.FileListener(sockFile)
	if err != nil {
		return nil, err
	}

	// as the docs for FileListener() indicate, closing the listener does not close sockFile
	// presumably because FileListener() duplicates the underlying descriptor, so close
	// sockFile now that we don't need it anymore
	if err := sockFile.Close(); err != nil {
		return nil, err
	}

	return tcpKeepAliveListener{fileListener.(*net.TCPListener)}, nil
}

// based on https://golang.org/src/net/http/server.go?s=52296:53789#L2126
// supposedly keeps us from leaking connections that never close (not sure if this applies behind a GCE load balancer)

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(3 * time.Minute)
	return conn, nil
}
