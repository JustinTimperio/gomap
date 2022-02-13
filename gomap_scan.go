package gomap

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// scanIPRange scans an entire cidr range for open ports
// I am fairly happy with this code since its just iterating
// over scanIPPorts. Most issues are deeper in the code.
func scanIPRange(laddr string, proto string, fastscan bool, stealth bool, proxyURL string) (RangeScanResult, error) {
	iprange := getLocalRange()
	hosts := createHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		scan, err := scanIPPorts(h, laddr, proto, fastscan, stealth, proxyURL)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

// scanIPPorts scans a list of ports on <hostname> <protocol>
func scanIPPorts(hostname string, laddr string, proto string, fastscan bool, stealth bool, proxyURL string) (*IPScanResult, error) {
	var results []portResult

	// checks if device is online
	addr, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}

	// This gets the device name. ('/etc/hostname')
	// This is typically a good indication of if a host is 'up'
	// but can cause false-negatives in certain situations.
	// For this reason when in fastscan mode, devices without
	// names are ignored but are fully scanned in slowmode.
	hname, err := net.LookupAddr(hostname)
	if fastscan {
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		hname = append(hname, "Unknown")
	}

	// Start prepping channels and vars for worker pool
	in := make(chan int)
	go func() {
		for i := 0; i <= 65535; i++ {
			in <- i
		}
		close(in)
	}()

	var list map[int]string
	var depth int

	if fastscan {
		list = commonlist
		depth = 50
	} else {
		list = detailedlist
		depth = 500
	}

	tasks := len(list)

	// Create results channel and worker function
	resultChannel := make(chan portResult, tasks)
	worker := func() {
		for port := range in {
			if service, ok := list[port]; ok {
				if stealth {
					scanPortSyn(resultChannel, proto, hostname, service, port, laddr, proxyURL)
				} else {
					scanPort(resultChannel, proto, hostname, service, port, proxyURL)
				}
			}
		}
	}

	// Deploy a pool of workers
	for i := 0; i < depth; i++ {
		go worker()
	}

	// Combines all results from resultChannel and return a IPScanResult
	for result := range resultChannel {
		results = append(results, result)
		fmt.Printf("\033[2K\rHost: %s | Ports Scanned %d/%d", hostname, len(results), tasks)

		if len(results) == tasks {
			close(resultChannel)
		}
	}

	return &IPScanResult{
		Hostname: hname[0],
		IP:       addr,
		Results:  results,
	}, nil
}

// scanPort scans a single ip port combo
// This detection method only works on some types of services
// but is a reasonable solution for this application
func scanPort(resultChannel chan<- portResult, protocol, hostname, service string, port int, proxyURL string) {
	result := portResult{Port: port, Service: service}
	address := hostname + ":" + strconv.Itoa(port)
	var conn net.Conn
	var err error
	var proxyDialer proxy.Dialer
	// use proxy dialer if proxyURL string is not empty
	if len(proxyURL) > 0 {
		u, uErr := url.Parse(proxyURL)
		pw, _ := u.User.Password()

		auth := &proxy.Auth{
			User:     u.User.Username(),
			Password: pw,
		}
		if uErr != nil {
			fmt.Println("Failed to obtain proxy dialer: ", err)
			return
		}
		// create a proxy dialer for SOCKS5 proxy
		if u.Scheme == "socks5" {
			proxyDialer, err = proxy.SOCKS5("ip4:tcp", address, auth, proxy.Direct)
			if err != nil {
				fmt.Printf("failed to create SOCKS5 proxy dialer: %s\n", err)
				return
			}
		} else {
			proxyDialer, err = proxy.FromURL(u, proxy.Direct)
			if err != nil {
				fmt.Printf("Failed to parse  " + proxyURL + " as a proxy: " + err.Error())
				return
			}
		}
		conn, err = proxyDialer.Dial(protocol, address)
	} else {
		conn, err = net.DialTimeout(protocol, address, 3*time.Second)
	}

	if err != nil {
		result.State = false
		resultChannel <- result
		return
	}

	defer conn.Close()
	result.State = true
	resultChannel <- result
}

// scanPortSyn scans a single ip port combo using a syn-ack
// This detection method again only works on some types of services
// but is a reasonable solution for this application
func scanPortSyn(resultChannel chan<- portResult, protocol, hostname, service string, port int, laddr string, proxyURL string) {
	result := portResult{Port: port, Service: service}
	ack := make(chan bool, 1)

	go recvSynAck(laddr, hostname, uint16(port), ack)
	sendSyn(laddr, hostname, uint16(random(10000, 65535)), uint16(port), proxyURL)

	select {
	case r := <-ack:
		result.State = r
		resultChannel <- result
		return
	case <-time.After(3 * time.Second):
		result.State = false
		resultChannel <- result
		return
	}
}
