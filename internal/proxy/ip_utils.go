package proxy

import (
	"net"
)

// parseCIDR парсит CIDR сеть
func parseCIDR(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// parseIP парсит IP адрес
func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}
