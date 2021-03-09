# gomap

![GitHub](https://img.shields.io/github/license/JustinTimperio/gomap)
[![Go Reference](https://pkg.go.dev/badge/github.com/JustinTimperio/gomap.svg)](https://pkg.go.dev/github.com/JustinTimperio/gomap)
[![Go Report Card](https://goreportcard.com/badge/github.com/JustinTimperio/gomap)](https://goreportcard.com/report/github.com/JustinTimperio/gomap)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/47e878568ce04a819e82af10d3734062)](https://www.codacy.com/gh/JustinTimperio/gomap/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=JustinTimperio/gomap&amp;utm_campaign=Badge_Grade)

## What is gomap?
Gomap is a fully self-contained nmap like module for Golang. Unlike other projects which provide nmap bindings or rely on other local dependencies, gomap is a fully implemented in Go. Since this is a small library, it only focuses on providing a few core features for applications that require a completely embedded solution. 


## Features
  - Parallel port scanning using go routines
  - Automated CIDR range scanning
  - Service perdiction by port number
  - Fast scanning for common ports only
  - Pure Go with zero dependencies
  - Easily integrated into other projects

## Example Usage
 1. Create `quickscan.go`
```go
   package main

   import (
	   "github.com/JustinTimperio/gomap"
   )

   func main() {
		scan := gomap.ScanRange()
		gomap.PrintRangeResults(scan)
	 }
```
 2. `go mod init`
 3. `go mod tidy`
 4. `go run quickscan.go`

## Example Outputs

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
 
```
