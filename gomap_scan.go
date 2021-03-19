package gomap

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// scanIPRange scans an entire cidr range for open ports
// I am fairly happy with this code since its just iterating
// over scanIPPorts. Most issues are deeper in the code.
func scanIPRange(proto string, fastscan bool, stealth bool) (RangeScanResult, error) {
	iprange := getLocalRange()
	hosts := createHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		scan, err := scanIPPorts(h, proto, fastscan, stealth)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

// scanIPPorts scans a list of ports on <hostname> <protocol>
func scanIPPorts(hostname string, proto string, fastscan bool, stealth bool) (*IPScanResult, error) {
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

	// Creates a pool of go routines to scan every port on
	// a given host in parrallel. Routines are limited to
	// 10 workers in parrallel to reduce port flooding
	in := make(chan int)
	go func() {
		for i := 0; i <= 65535; i++ {
			in <- i
		}

		close(in)
	}()

	var list map[int]string
	if fastscan {
		list = commonlist
	} else {
		list = detailedlist
	}

	tasks := len(list)

	resultChannel := make(chan portResult, tasks)
	worker := func() {
		for port := range in {
			if service, ok := list[port]; ok {
				if stealth {
					scanPortSyn(resultChannel, proto, hostname, service, port)
				} else {
					scanPort(resultChannel, proto, hostname, service, port)
				}
			}
		}
	}

	for i := 0; i < 10; i++ {
		go worker()
	}

	// Combines all results from resultChannel and
	// returns a IPScanResult struct
	for result := range resultChannel {
		results = append(results, result)
		fmt.Printf("\033[2K\rHost: %s | Ports Scanned %d/%d", hostname, len(results), tasks)

		if len(results) == tasks {
			close(resultChannel)
		}
	}

	return &IPScanResult{
		hostname: hname[0],
		ip:       addr,
		results:  results,
	}, nil
}

// scanPort scans a single ip port combo
// This detection method only works on some types of services
// but is a reasonable solution for this application
func scanPort(resultChannel chan<- portResult, protocol, hostname, service string, port int) {
	result := portResult{Port: port, Service: service}
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, 3*time.Second)
	if err != nil {
		result.State = false
		resultChannel <- result
		return
	}

	defer conn.Close()
	result.State = true
	resultChannel <- result
}

// scanPort scans a single ip port combo
// This detection method only works on some types of services
// but is a reasonable solution for this application
func scanPortSyn(resultChannel chan<- portResult, protocol, hostname, service string, port int) {
	result := portResult{Port: port, Service: service}
	address := hostname + ":" + strconv.Itoa(port)

	conn, err := net.DialTimeout(protocol, address, 3*time.Second)
	if err != nil {
		result.State = false
		resultChannel <- result
		return
	}

	defer conn.Close()
	result.State = true
	resultChannel <- result
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
