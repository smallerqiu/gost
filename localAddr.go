package gost

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"
)

var localAddrKey = "localAddr"

func GetIP(conn net.Conn) (ip net.IP) {
	IP := conn.LocalAddr().(*net.TCPAddr).IP
	if IP != nil && !IP.IsPrivate() && !IP.IsLoopback() {
		return IP
	}
	return nil
}

func getContext(conn net.Conn, parentCtx context.Context) (ctx context.Context) {
	IP := GetIP(conn)
	if IP != nil {
		return context.WithValue(parentCtx, localAddrKey, IP)
	}
	return parentCtx
}

func getIP(ctx context.Context) (ip net.IP) {
	if v := ctx.Value(localAddrKey); v != nil {
		if ip, ok := v.(net.IP); ok && !ip.IsPrivate() && !ip.IsLoopback() {
			return ip
		}
	}
	return nil
}
func GetSshIP(conn ssh.ConnMetadata) (ip net.IP) {
	IP := conn.LocalAddr().(*net.TCPAddr).IP
	if IP != nil && !IP.IsPrivate() && !IP.IsLoopback() {
		return IP
	}
	return nil
}

func getLocalAddr(ctx context.Context, options *ChainOptions) (addr net.Addr) {
	ip := getIP(ctx)
	if ip == nil && options != nil {
		ip = options.IP
	}
	if ip != nil {
		addr = &net.TCPAddr{
			IP:   ip,
			Port: 0,
		}
	}
	return
}
