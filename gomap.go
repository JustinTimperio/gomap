package gomap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
)

// IPScanResult contains the results of a scan on a single ip
type IPScanResult struct {
	Hostname string
	IP       []net.IP
	Results  []portResult
}

// JsonRange contains a slice of of JsonIP results
type JsonRange struct {
	results []JsonIP
}

// JsonIP contains the results for a single JSON entry
type JsonIP struct {
	IP       string
	Hostname string
	Active   bool
	Ports    []string
}

type portResult struct {
	Port    int
	State   bool
	Service string
}

type tcpHeader struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Flags         uint16
	Window        uint16
	ChkSum        uint16
	UrgentPointer uint16
}

type tcpOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// RangeScanResult contains multiple IPScanResults
type RangeScanResult []*IPScanResult

// ScanIP scans a single IP for open ports
func ScanIP(hostname string, proto string, fastscan bool, stealth bool) (*IPScanResult, error) {
	laddr, err := getLocalIP()
	if err != nil {
		return nil, err
	}

	if stealth {
		if canSocketBind(laddr) == false {
			return nil, fmt.Errorf("socket: operation not permitted")
		}
	}
	return scanIPPorts(hostname, laddr, proto, fastscan, stealth)
}

// ScanRange scans every address on a CIDR for open ports
func ScanRange(proto string, fastscan bool, stealth bool) (RangeScanResult, error) {
	laddr, err := getLocalIP()
	if err != nil {
		return nil, err
	}

	if stealth {
		if canSocketBind(laddr) == false {
			return nil, fmt.Errorf("socket: operation not permitted")
		}
	}
	return scanIPRange(laddr, proto, fastscan, stealth)
}

// String with the results of a single scanned IP
func (results *IPScanResult) String() string {
	b := bytes.NewBuffer(nil)
	ip := results.IP[len(results.IP)-1]

	fmt.Fprintf(b, "\nHost: %s (%s)\n", results.Hostname, ip)

	active := false
	for _, r := range results.Results {
		if r.State {
			active = true
			break
		}
	}
	if active {
		fmt.Fprintf(b, "\t|     %s	%s\n", "Port", "Service")
		fmt.Fprintf(b, "\t|     %s	%s\n", "----", "-------")
		for _, v := range results.Results {
			if v.State {
				fmt.Fprintf(b, "\t|---- %d	%s\n", v.Port, v.Service)
			}
		}
	} else if results.Hostname != "Unknown" {
		fmt.Fprintf(b, "\t|---- %s\n", "No Open Ports Found")
	}
	return b.String()
}

// String with the results of multiple scanned IP's
func (results RangeScanResult) String() string {
	b := bytes.NewBuffer(nil)
	for _, r := range results {
		ip := r.IP[len(r.IP)-1]

		fmt.Fprintf(b, "\nHost: %s (%s)\n", r.Hostname, ip)
		active := false

		for _, r := range r.Results {
			if r.State {
				active = true
				break
			}
		}
		if active {
			fmt.Fprintf(b, "\t|     %s	%s\n", "Port", "Service")
			fmt.Fprintf(b, "\t|     %s	%s\n", "----", "-------")
			for _, v := range r.Results {
				if v.State {
					fmt.Fprintf(b, "\t|---- %d	%s\n", v.Port, v.Service)
				}
			}
		} else if r.Hostname != "Unknown" {
			fmt.Fprintf(b, "\t|---- %s\n", "No Open Ports Found")
		}
	}

	return b.String()
}

// Contains a marshaled struct containing the results for a ip scan
func (results *IPScanResult) Json() (string, error) {
	var ipdata JsonIP
	fmt.Println(results.IP)
	ipdata.IP = fmt.Sprintf("%s", results.IP[len(results.IP)-1])
	ipdata.Hostname = results.Hostname

	active := false
	for _, r := range results.Results {
		if r.State {
			active = true
			break
		}
	}
	ipdata.Active = active

	if active {
		for _, v := range results.Results {
			if v.State {
				entry := fmt.Sprintf("%d: %s", v.Port, v.Service)
				ipdata.Ports = append(ipdata.Ports, entry)
			}
		}
	}

	j, err := json.MarshalIndent(ipdata, "", "	")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// Contains a marshaled struct containing the results for a range scan
func (results RangeScanResult) Json() (string, error) {
	var data JsonRange

	for _, r := range results {
		var ipdata JsonIP
		ipdata.IP = fmt.Sprintf("%s", r.IP[len(r.IP)-1])
		ipdata.Hostname = r.Hostname

		active := false
		for _, r := range r.Results {
			if r.State {
				active = true
				break
			}
		}
		ipdata.Active = active

		if active {
			for _, v := range r.Results {
				if v.State {
					entry := fmt.Sprintf("%d: %s", v.Port, v.Service)
					ipdata.Ports = append(ipdata.Ports, entry)
				}
			}
		}
		data.results = append(data.results, ipdata)
	}

	j, err := json.MarshalIndent(data.results, "", "	")
	if err != nil {
		return "", err
	}
	return string(j), nil
}
