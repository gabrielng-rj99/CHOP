package main

import (
	"fmt"
	"strings"
)

// PrintOptionalFieldHint prints instructions for optional field handling
// This should be called once before displaying Current/New field prompts
func PrintOptionalFieldHint() {
	fmt.Println("(Use '-' to set blank, leave empty to keep current value)")
}

// HandleOptionalField processes optional field input
// Returns: (newValue, shouldUpdate, shouldClear)
// - "-" returns ("", true, true) - clear the field
// - "" returns ("", false, false) - keep current value
// - other returns (value, true, false) - update to new value
func HandleOptionalField(input string) (string, bool, bool) {
	input = strings.TrimSpace(input)

	if input == "-" {
		return "", true, true
	}
	if input == "" {
		return "", false, false
	}
	return input, true, false
}
