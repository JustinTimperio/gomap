# gomap

![GitHub](https://img.shields.io/github/license/JustinTimperio/gomap)
[![Go Reference](https://pkg.go.dev/badge/github.com/JustinTimperio/gomap.svg)](https://pkg.go.dev/github.com/JustinTimperio/gomap)
[![Go Report Card](https://goreportcard.com/badge/github.com/JustinTimperio/gomap)](https://goreportcard.com/report/github.com/JustinTimperio/gomap)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/a338ee8deaad42328d78f98f6e6481a3)](https://www.codacy.com/gh/JustinTimperio/gomap/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=JustinTimperio/gomap&amp;utm_campaign=Badge_Grade)

## What is gomap?
Gomap is a fully self-contained nmap like module for Golang. Unlike other projects which provide nmap C bindings or rely on other local dependencies, gomap is a fully implemented in pure Go. Gomap imports zero non-core modules making it ideal for applications that have zero control on the clients operating system. Since this is a small library, it only focuses on providing a few core features. For the most part its API is stable with changes being applied to its unexposed internal scanning functions.


## Features
  - Parallel port scanning using go routines
  - Automated CIDR range scanning
  - Service prediction by port number
  - SYN (Silent) Scanning Mode
  - UDP Scanning (Non-Stealth)
  - Fast and detailed scanning for common ports
  - Pure Go with zero dependencies
  - Easily integrated into other projects

## Upcoming Features
  - CIDR range size detection

## Example Usage - 1
Performs a fastscan for the most common ports on every IP on a local range
### Create Files
 1. Create `quickscan.go`
```go
package main

import (
	"fmt"

	"github.com/JustinTimperio/gomap"
)

func main() {
	var (
		proto    = "tcp"
		fastscan = true
		syn      = false
	)

	scan, err := gomap.ScanRange(proto, fastscan, syn)
	if err != nil {
		// handle error
	}
	fmt.Printf(scan.String())
}
```
 2. `go mod init quickscan`
 3. `go mod tidy`
 4. `go run quickscan.go`

### Example Output

```
Host: computer-name (192.168.1.132)
        |     Port      Service
        |     ----      -------
        |---- 22        ssh
 
Host: server-nginx (192.168.1.143)
        |     Port      Service
        |     ----      -------
        |---- 443       https
        |---- 80        http
        |---- 22        ssh
 
Host: server-minio (192.168.1.112)
        |     Port      Service
        |     ----      -------
        |---- 22        ssh

Host: some-phone (192.168.1.155)
        |- No Open Ports
```

## Example Usage - 2
Performs a detailed stealth scan on a single IP

### Create Files
 1. Create `stealthmap.go`
```go
package main

import (
	"fmt"

	"github.com/JustinTimperio/gomap"
)

func main() {
	// Stealth scans MUST be run as root/admin
	var (
		fastscan = false
		syn      = true
		proto    = "tcp"
		ip       = "192.168.1.120"
	)

	scan, err := gomap.ScanIP(ip, proto, fastscan, syn)
	if err != nil {
		// handle error
	}
	fmt.Printf(scan.String())
}
```
 2. `go mod init stealthmap`
 3. `go mod tidy`
 4. `sudo go run stealthmap.go`

### Example Output

```
Host: 192.168.1.120 | Ports Scanned 3236/3236
Host: Voyager (192.168.1.120)
        |     Port      Service
        |     ----      -------
        |---- 22        SSH Remote Login Protocol
        |---- 80        World Wide Web HTTP
        |---- 443       HTTP protocol over TLS/SSL
```
