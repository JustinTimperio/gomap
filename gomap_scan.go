package gomap

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// scanIPRange scans an entire cidr range for open ports
// I am fairly happy with this code since its just iterating
// over scanIPPorts. Most issues are deeper in the code.
func scanIPRange(proto string, fastscan bool) (RangeScanResult, error) {
	var results []IPScanResult
	iprange := getLocalRange()
	hosts := createHostRange(iprange)

	for _, h := range hosts {
		scan, err := scanIPPorts(h, proto, fastscan)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}
	rangeScan := RangeScanResult{all: results}
	return rangeScan, nil
}

// scanIPPorts scans a list of ports on <hostname> <protocol>
func scanIPPorts(hostname string, proto string, fastscan bool) (IPScanResult, error) {
	var (
		results []portResult
		scanned IPScanResult
		tasks   int
		start   = 0
		end     = 50000
	)

	// checks if device is online
	addr, err := net.LookupIP(hostname)
	if err != nil {
		return scanned, err
	}

	// This gets the device name. ('/etc/hostname')
	// This is typically a good indication of if a host is 'up'
	// but can cause false-negatives in certain situations.
	// For this reason when in fastscan mode, devices without
	// names are ignored but are fully scanned in slowmode.
	hname, err := net.LookupAddr(hostname)
	if fastscan {
		if err != nil {
			return scanned, err
		}
		tasks = len(commonlist)

	} else {
		if err != nil {
			hname = append(hname, "Unknown")
		}
		tasks = len(detailedlist)
	}

	// Opens pool of connections to crawl ports
	// This process results in a large number of false-negatives
	// due to timeouts when scanning a large number of ports at once.
	// I am open to new solutions to this brick of code
	resultChannel := make(chan portResult, tasks)
	if fastscan {
		for i := start; i <= end; i++ {
			if service, ok := commonlist[i]; ok {
				go scanPort(resultChannel, proto, hostname, service, i, fastscan)
			}
		}
	} else {
		for i := start; i <= end; i++ {
			if service, ok := detailedlist[i]; ok {
				go scanPort(resultChannel, proto, hostname, service, i, fastscan)
			}
		}
	}

	// This waits for all routines to finish.
	// Overall this has been more performant than wait-groups
	// and it allows for an active counter to display progress
	for {
		if len(resultChannel) == tasks {
			close(resultChannel)
			break
		} else {
			fmt.Printf("\033[2K\rHost: %s | Ports Scanned %d/%d", hostname, len(resultChannel), tasks)
			time.Sleep(1000 * time.Millisecond)
		}
	}

	// Combines all results from resultChannel and
	// returns a IPScanResult struct
	for result := range resultChannel {
		results = append(results, result)
	}

	scanned = IPScanResult{
		hostname: hname[0],
		ip:       addr,
		results:  results,
	}
	return scanned, nil
}

// scanPort scans a single ip port combo
func scanPort(resultChannel chan<- portResult, protocol, hostname, service string, port int, fastscan bool) {
	// To deal with host overloading this proccess waits a
	// random amount of time before moving on.
	// This spaces out the execution of all the go routines by a few milliseconds
	r := rand.Intn(500)
	time.Sleep(time.Duration(r) * time.Microsecond)

	// Dials a port with a timeout
	// This only works on some types of services
	// but is a reasonable solution for this application
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
	return
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
