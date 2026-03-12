package gost

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"
)

var localAddrKey = "localAddr"

func getIP(conn net.Conn) (ip net.IP) {
	IP := conn.LocalAddr().(*net.TCPAddr).IP
	if IP != nil && !IP.IsPrivate() && !IP.IsLoopback() {
		return IP
	}
	return nil
}

func getContext1(ip net.IP) (ctx context.Context) {
	ctx = context.Background()
	if ip != nil {
		return context.WithValue(ctx, localAddrKey, ip)
	}
	return
}
func getContext(conn net.Conn, parentCtx context.Context) (ctx context.Context) {
	IP := getIP(conn)
	if IP != nil {
		return context.WithValue(parentCtx, localAddrKey, IP)
	}
	return parentCtx
}

func GetIP(ctx context.Context) (ip net.IP) {
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

func getLocalAddr(ctx context.Context) (addr net.Addr) {
	ip := GetIP(ctx)
	if ip != nil {
		addr = &net.TCPAddr{
			IP:   ip,
			Port: 0,
		}
	}
	return
}
