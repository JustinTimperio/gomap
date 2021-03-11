package gomap_test

import (
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	fastscan := true
	results := gomap.ScanRange(fastscan)
	gomap.PrintRangeResults(results)
	//
	// fastscan := false
	// results := gomap.ScanIP("192.168.1.120", fastscan)
	// gomap.PrintIPResults(results)

}
