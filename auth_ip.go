package gost

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

var whiteList atomic.Value

type IPWhiteList struct {
	networks []*net.IPNet
}

func NewIPWhiteList(list []string) (*IPWhiteList, error) {
	wl := &IPWhiteList{}
	for _, item := range list {
		if strings.Contains(item, "/") {
			_, netw, err := net.ParseCIDR(item)
			if err != nil {
				return nil, err
			}
			wl.networks = append(wl.networks, netw)
		} else {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("invalid ip: %s", item)
			}
			mask := net.CIDRMask(32, 32)
			wl.networks = append(wl.networks, &net.IPNet{
				IP:   ip,
				Mask: mask,
			})
		}
	}

	return wl, nil
}

func (w *IPWhiteList) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, netw := range w.networks {
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

func LoadIPWhiteList(list []string) error {
	wl, err := NewIPWhiteList(list)
	if err != nil {
		return err
	}
	whiteList.Store(wl)
	return nil
}

func isWhiteIP(ip net.IP) bool {
	wl := whiteList.Load().(*IPWhiteList)
	return wl.Contains(ip)
}
