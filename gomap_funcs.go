package gomap

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

func canSocketBind(laddr string) bool {
	// Check if user can listen on socket
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return false
	}

	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

// createHostRange converts a input ip addr string to a slice of ips on the cidr
func createHostRange(netw string) []string {
	_, ipv4Net, err := net.ParseCIDR(netw)
	if err != nil {
		log.Fatal(err)
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)

	var hosts []string
	for i := start + 1; i <= finish-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}

	return hosts
}

// getLocalRange returns local ip range or defaults on error to most common
func getLocalRange() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "192.168.1.0/24"
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				split := strings.Split(ipnet.IP.String(), ".")
				return split[0] + "." + split[1] + "." + split[2] + ".0/24"
			}
		}
	}
	return "192.168.1.0/24"
}

// getLocalRange returns local ip range or defaults on error to most common
func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), err
			}
		}
	}
	return "", fmt.Errorf("No IP Found")
}

func dialTarget(scanOption *ScanOption, raddr, protocol string) (net.Conn, error) {
	var conn net.Conn
	var err error
	var dialerErr error
	var proxyDialer proxy.Dialer

	if scanOption != nil && scanOption.ProxyURL != nil {
		u, uErr := url.Parse(*scanOption.ProxyURL)
		pw, _ := u.User.Password()

		auth := &proxy.Auth{
			User:     u.User.Username(),
			Password: pw,
		}
		if uErr != nil {
			return nil, fmt.Errorf("failed to obtain proxy dialer: %v", err)
		}
		// create a proxy dialer for SOCKS5 proxy
		if u.Scheme == "socks5" {
			proxyDialer, dialerErr = proxy.SOCKS5(protocol, u.Host, auth, proxy.Direct)
			if dialerErr != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 proxy dialer: %s", err)
			}
		} else {
			proxyDialer, dialerErr = proxy.FromURL(u, proxy.Direct)
			if dialerErr != nil {
				return nil, fmt.Errorf("Failed to parse  " + *scanOption.ProxyURL + " as a proxy: " + err.Error())
			}
		}
		conn, err = proxyDialer.Dial(protocol, raddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s: %s via proxy", raddr, err)
		}
	} else {
		conn, err = net.Dial(protocol, raddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s: %s", raddr, err)
		}
	}

	return conn, nil
}
