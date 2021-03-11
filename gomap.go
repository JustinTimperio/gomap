package gomap

import (
	"fmt"
	"net"
)

type portResult struct {
	Port    int
	State   bool
	Service string
}

// IPScanResult contains the results of a scan on a single ip
type IPScanResult struct {
	hostname string
	ip       []net.IP
	results  []portResult
}

// RangeScanResult contains multiple IPScanResults
type RangeScanResult struct {
	all []IPScanResult
}

// ScanIP scans a single IP for open ports
func ScanIP(hostname string, fastscan bool) IPScanResult {
	ipScan, err := scanIPPorts(hostname, "tcp", fastscan)
	if err != nil {
		fmt.Println(err)
	}
	return ipScan
}

// ScanRange scans every address on a CIDR for open ports
func ScanRange(fastscan bool) RangeScanResult {
	rangeScan, err := scanIPRange("tcp", fastscan)
	if err != nil {
		fmt.Println(err)
	}
	return rangeScan
}

// PrintIPResults prints the results of a single ScanIp
func PrintIPResults(results IPScanResult) {
	ip := results.ip[len(results.ip)-1]
	fmt.Printf("\nHost: %s (%s)\n", results.hostname, ip.String())
	active := false

	for _, r := range results.results {
		if r.State {
			active = true
			break
		}
	}
	if active {
		fmt.Printf("\t|     %s	%s\n", "Port", "Service")
		fmt.Printf("\t|     %s	%s\n", "----", "-------")
		for _, v := range results.results {
			if v.State {
				fmt.Printf("\t|---- %d	%s\n", v.Port, v.Service)
			}
		}
	} else if results.hostname != "Unknown" {
		fmt.Printf("\t|---- %s\n", "No Open Ports Found")
	}
}

// PrintRangeResults prints the results of a ScanRange
func PrintRangeResults(results RangeScanResult) {
	for _, r := range results.all {
		PrintIPResults(r)
	}
}
