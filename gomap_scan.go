package gomap

import (
	"fmt"
	"net"
	"strconv"
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
	var depth int

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

	// Sets the number of workers
	if stealth {
		depth = 500
	} else {
		depth = 500
	}

	for i := 0; i < depth; i++ {
		go worker()
	}

	// Combines all results from resultChannel and
	// returns a IPScanResult strucu
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

func scanPortSyn(resultChannel chan<- portResult, protocol, hostname, service string, port int) {
	result := portResult{Port: port, Service: service}
	laddr, _ := getLocalIP()
	ack := make(chan bool, 1)

	go recvSynAck(laddr, hostname, uint16(port), ack)
	sendSyn(laddr, hostname, uint16(random(10000, 65535)), uint16(port))

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
