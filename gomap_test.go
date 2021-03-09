package gomap_test

import (
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	// results := gomap.ScanIP("192.168.1.120")
	// gomap.PrintIPResults(results)
	// fmt.Print(" ")
	results := gomap.ScanRange()
	gomap.PrintRangeResults(results)

}
