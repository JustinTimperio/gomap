package gomap

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func scanIPRange(proto string) (RangeScanResult, error) {
	var results []IPScanResult
	iprange := GetLocalRange()
	hosts := createHostRange(iprange)

	for _, h := range hosts {
		scan, err := scanIPPorts(h, proto)

		if err != nil {
			continue
		}

		results = append(results, scan)
	}
	rangeScan := RangeScanResult{all: results}
	return rangeScan, nil
}

func scanIPPorts(hostname string, proto string) (IPScanResult, error) {
	var (
		results []portResult
		scanned IPScanResult
		wg      sync.WaitGroup
		start   = 0
		end     = 50000
	)

	addr, err := net.LookupIP(hostname)
	if err != nil {
		return scanned, err
	}

	// gets devices name
	hname, err := net.LookupAddr(hostname)
	if err != nil {
		return scanned, err
	}

	// opens pool of connections
	resultChannel := make(chan portResult, end-start)
	for i := start; i <= end; i++ {
		if service, ok := common[i]; ok {
			wg.Add(1)
			go scanPort(proto, hostname, service, i, resultChannel, &wg)
		}
	}

	wg.Wait()
	close(resultChannel)

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

func scanPort(protocol, hostname, service string, port int, resultChannel chan portResult, wg *sync.WaitGroup) {
	defer wg.Done()

	result := portResult{Port: port, Service: service}
	address := hostname + ":" + strconv.Itoa(port)

	conn, err := net.DialTimeout(protocol, address, 1*time.Second)
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

// GetLocalRange returns local ip range or defaults on error to most common
func GetLocalRange() string {
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
