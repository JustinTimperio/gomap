package gomap_test

import (
	"fmt"
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	var (
		proto    = "tcp"
		fastscan = true
		stealth  = false
		// proxy    = "socks5://127.0.0.1:1080"
	)

	results, err := gomap.ScanIP("192.168.1.1", proto, fastscan, stealth, nil)
	// results, err := gomap.ScanRange(proto, fastscan, stealth, &proxy)
	if err != nil {
		panic(err)
	} else {
		fmt.Println(results.String())
	}

	j, err := results.Json()
	if err != nil {
		panic(err)
	} else {
		fmt.Println(j)
	}
}
