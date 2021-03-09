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

type IPScanResult struct {
	hostname string
	ip       []net.IP
	results  []portResult
}

type RangeScanResult struct {
	all []IPScanResult
}

func ScanRange() RangeScanResult {
	rangeScan, err := scanIPRange("tcp")

	if err != nil {
		fmt.Println(err)
	}
	return rangeScan
}

func ScanIP(hostname string) IPScanResult {
	ipScan, err := scanIPPorts(hostname, "tcp")

	if err != nil {
		fmt.Println(err)
	}
	return ipScan
}

func PrintIPResults(results IPScanResult) {
	ip := results.ip[len(results.ip)-1]
	fmt.Printf("Host: %s (%s)\n", results.hostname, ip.String())

	fmt.Printf("\t|     %s	%s\n", "Port", "Service")
	fmt.Printf("\t|     %s	%s\n", "----", "-------")
	for _, v := range results.results {
		if v.State {
			fmt.Printf("\t|---- %d	%s\n", v.Port, v.Service)
		}
	}
}

func PrintRangeResults(results RangeScanResult) {
	for _, r := range results.all {
		ip := r.ip[len(r.ip)-1]
		fmt.Printf("Host: %s (%s)\n", r.hostname, ip.String())

		fmt.Printf("\t|     %s	%s\n", "Port", "Service")
		fmt.Printf("\t|     %s	%s\n", "----", "-------")
		for _, v := range r.results {
			if v.State {
				fmt.Printf("\t|---- %d	%s\n", v.Port, v.Service)
			}
		}
		fmt.Println(" ")
	}
}
