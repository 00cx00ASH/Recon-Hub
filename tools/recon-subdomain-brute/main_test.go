package main

import (
	"reflect"
	"testing"
)

func TestCleanHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://Exemplo.com/": "exemplo.com",
		"*.exemplo.com":        "exemplo.com",
		"exemplo.com:443":      "exemplo.com",
		"  exemplo.com.  ":     "exemplo.com",
	} {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestMergeWordsDedupPreservesOrderAndPutsExtraFirst(t *testing.T) {
	got := mergeWords("custom1, custom2", []string{"www", "custom1", "api"})
	want := []string{"custom1", "custom2", "www", "api"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestMergeWordsHandlesEmptyExtra(t *testing.T) {
	got := mergeWords("", []string{"www", "api"})
	want := []string{"www", "api"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}
