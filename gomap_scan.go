package gomap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// scanIPRange scans an entire cidr range for open ports
// I am fairly happy with this code since its just iterating
// over scanIPPorts. Most issues are deeper in the code.
func scanIPRange(
	ctx context.Context, laddr string, proto string, fastscan bool, stealth bool,
) (RangeScanResult, error) {
	iprange := getLocalRange()
	hosts := createHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		scan, err := scanIPPorts(ctx, h, laddr, proto, fastscan, stealth)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

// scanIPPorts scans a list of ports on <hostname> <protocol>
func scanIPPorts(
	ctx context.Context, hostname string, laddr string, proto string, fastscan bool, stealth bool,
) (*IPScanResult, error) {
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
		defer close(in)

		for i := 0; i <= 65535; i++ {
			select {
			case <-ctx.Done():
				return
			case in <- i:
			}
		}
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
	resultChannel := make(chan portResult)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case port, ok := <-in:
				if !ok {
					return
				}

				if service, ok := list[port]; ok {
					if stealth {
						scanPortSyn(resultChannel, proto, hostname, service, port, laddr)
					} else {
						scanPort(resultChannel, proto, hostname, service, port)
					}
				}
			}

		}
	}

	// Deploy a pool of workers
	for i := 0; i < depth; i++ {
		wg.Add(1)
		go worker()
	}

	var results []portResult
	go func() {
		// Combines all results from resultChannel and return a IPScanResult
		for result := range resultChannel {
			results = append(results, result)
			fmt.Printf("\033[2K\rHost: %s | Ports Scanned %d/%d", hostname, len(results), tasks)
		}
	}()

	wg.Wait()

	close(resultChannel)

	return &IPScanResult{
		Hostname: hname[0],
		IP:       addr,
		Results:  results,
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

// scanPortSyn scans a single ip port combo using a syn-ack
// This detection method again only works on some types of services
// but is a reasonable solution for this application
func scanPortSyn(resultChannel chan<- portResult, protocol, hostname, service string, port int, laddr string) {
	result := portResult{Port: port, Service: service}
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
