package dataplane

import (
	"testing"
	"time"
)

func TestParseFan(t *testing.T) {
	fan, ok := ParseFan("8 6/minute 60 600\n")
	if !ok || fan.Burst != 8 || fan.Rate != 6 || fan.Unit != 60 || fan.Pair != time.Minute || fan.Suspect != 10*time.Minute {
		t.Fatalf("parsed %+v %v", fan, ok)
	}
	if refill := fan.Refill(); refill != 81*time.Second {
		t.Fatalf("refill %v", refill)
	}
	if fan, ok := ParseFan("20 1/second 30 300"); !ok || fan.Unit != 1 || fan.Refill() != 21*time.Second {
		t.Fatalf("parsed %+v %v", fan, ok)
	}
	for _, line := range []string{"", "off", "8 6 60 600", "0 6/minute 60 600", "8 0/minute 60 600", "8 6/hour 60 600", "8 6/minute 0 600", "8 6/minute 60 0", "8 6/minute 60"} {
		if _, ok := ParseFan(line); ok {
			t.Errorf("%q parsed", line)
		}
	}
}
