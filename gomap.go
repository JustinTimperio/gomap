package gomap

import (
	"bytes"
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
type RangeScanResult []*IPScanResult

// ScanIP scans a single IP for open ports
func ScanIP(hostname string, proto string, fastscan bool, stealth bool) (*IPScanResult, error) {
	return scanIPPorts(hostname, proto, fastscan, stealth)
}

// ScanRange scans every address on a CIDR for open ports
func ScanRange(fastscan bool, proto string, stealth bool) (RangeScanResult, error) {
	return scanIPRange(proto, fastscan, stealth)
}

// String with the results of a single scanned IP
func (results *IPScanResult) String() string {
	b := bytes.NewBuffer(nil)
	ip := results.ip[len(results.ip)-1]

	fmt.Fprintf(b, "\nHost: %s (%s)\n", results.hostname, ip)

	active := false
	for _, r := range results.results {
		if r.State {
			active = true
			break
		}
	}
	if active {
		fmt.Fprintf(b, "\t|     %s	%s\n", "Port", "Service")
		fmt.Fprintf(b, "\t|     %s	%s\n", "----", "-------")
		for _, v := range results.results {
			if v.State {
				fmt.Fprintf(b, "\t|---- %d	%s\n", v.Port, v.Service)
			}
		}
	} else if results.hostname != "Unknown" {
		fmt.Fprintf(b, "\t|---- %s\n", "No Open Ports Found")
	}
	return b.String()
}

// String with the results of multiple scanned IP's
func (results RangeScanResult) String() string {
	b := bytes.NewBuffer(nil)
	for _, r := range results {
		ip := r.ip[len(r.ip)-1]

		fmt.Fprintf(b, "\nHost: %s (%s)\n", r.hostname, ip)
		active := false

		for _, r := range r.results {
			if r.State {
				active = true
				break
			}
		}
		if active {
			fmt.Fprintf(b, "\t|     %s	%s\n", "Port", "Service")
			fmt.Fprintf(b, "\t|     %s	%s\n", "----", "-------")
			for _, v := range r.results {
				if v.State {
					fmt.Fprintf(b, "\t|---- %d	%s\n", v.Port, v.Service)
				}
			}
		} else if r.hostname != "Unknown" {
			fmt.Fprintf(b, "\t|---- %s\n", "No Open Ports Found")
		}
	}

	return b.String()
}
