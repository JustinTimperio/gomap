package gomap

import (
	"net"
	"strconv"
	"sync"
	"time"
)

func scanRange() {

}

func scanIP(hostname string, ports []int, protocol string) (IPScanResult, error) {
	var (
		results []portResult
		scanned IPScanResult
		wg      sync.WaitGroup
	)

	addr, err := net.LookupIP(hostname)
	if err != nil {
		return scanned, err
	}

	resultChannel := make(chan portResult, len(ports))

	for _, i := range ports {
		if service, ok := common[i]; ok {
			wg.Add(1)
			go scanPort(protocol, hostname, service, i, resultChannel, &wg)
		}
	}

	wg.Wait()
	close(resultChannel)

	for result := range resultChannel {
		results = append(results, result)
	}

	scanned = IPScanResult{
		hostname: hostname,
		ip:       addr,
		results:  results,
	}

	return scanned, nil
}

func scanPort(protocol, hostname, service string, port int, resultChannel chan portResult, wg *sync.WaitGroup) {
	defer wg.Done()

	result := portResult{
		Port:    port,
		Service: service,
	}

	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, 1*time.Second)
	defer conn.Close()

	if err != nil {
		result.State = false
		resultChannel <- result
		return
	}

	result.State = true
	resultChannel <- result
	return
}
