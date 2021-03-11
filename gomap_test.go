package gomap_test

import (
	"fmt"
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	fastscan := true
	results := gomap.ScanRange(fastscan)
	// results := gomap.ScanIP("192.168.1.120", fastscan)

	fmt.Printf(results.String())

}
