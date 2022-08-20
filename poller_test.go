package onvmpoller

import (
	"testing"
)

func TestCreate(t *testing.T) {
	onvmpoll.Create()
}

func TestString(t *testing.T) {
	s := onvmpoll.String()
	t.Log(s)
}
