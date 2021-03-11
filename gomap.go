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

// Provides a string that prints the results of a single ScanIp
func (results *IPScanResult) String() string {
	b := bytes.NewBuffer(nil)
	ip := results.ip[len(results.ip)-1]
	b.WriteString(fmt.Sprintf("\nHost: %s (%s)\n", results.hostname, ip.String()))
	active := false

	for _, r := range results.results {
		if r.State {
			active = true
			break
		}
	}
	if active {
		b.WriteString(fmt.Sprintf("\t|     %s	%s\n", "Port", "Service"))
		b.WriteString(fmt.Sprintf("\t|     %s	%s\n", "----", "-------"))
		for _, v := range results.results {
			if v.State {
				b.WriteString(fmt.Sprintf("\t|---- %d	%s\n", v.Port, v.Service))
			}
		}
	} else if results.hostname != "Unknown" {
		b.WriteString(fmt.Sprintf("\t|---- %s\n", "No Open Ports Found"))
	}
	return b.String()
}

// Provides a string that prints the results of a multiple ScanIP's
func (results *RangeScanResult) String() string {
	b := bytes.NewBuffer(nil)
	for _, r := range results.all {
		ip := r.ip[len(r.ip)-1]
		b.WriteString(fmt.Sprintf("\nHost: %s (%s)\n", r.hostname, ip.String()))
		active := false

		for _, r := range r.results {
			if r.State {
				active = true
				break
			}
		}
		if active {
			b.WriteString(fmt.Sprintf("\t|     %s	%s\n", "Port", "Service"))
			b.WriteString(fmt.Sprintf("\t|     %s	%s\n", "----", "-------"))
			for _, v := range r.results {
				if v.State {
					b.WriteString(fmt.Sprintf("\t|---- %d	%s\n", v.Port, v.Service))
				}
			}
		} else if r.hostname != "Unknown" {
			b.WriteString(fmt.Sprintf("\t|---- %s\n", "No Open Ports Found"))
		}

	}
	return b.String()
}
