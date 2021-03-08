package gomap

import (
	"fmt"
	"net"
)

type srange struct {
	Start, End int
}

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

func ScanIP(hostname string) IPScanResult {
	ports := createPortRange(srange{Start: 1, End: 10000})
	scanned, err := scanIP(hostname, ports, "tcp")

	if err != nil {
		fmt.Println(err)
		return scanned
	}
	return scanned
}

func PrintResults(results IPScanResult) {
	ip := results.ip[len(results.ip)-1]
	fmt.Printf("Open ports for %s (%s)\n", results.hostname, ip.String())

	for _, v := range results.results {
		if v.State {
			fmt.Printf("%d	%s\n", v.Port, v.Service)
		}
	}
}
