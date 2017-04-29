package main

import "testing"

func assert(t *testing.T, expected interface{}, actual interface{}) {

	if actual != expected {
		t.Errorf("\nexpected: %v \ngot: %v", expected, actual)
	}
}

func TestGetAcceptHash(t *testing.T) {
	assert(t, getAcceptHash("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
}
