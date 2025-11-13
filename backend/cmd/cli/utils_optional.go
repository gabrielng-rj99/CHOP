package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
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

func clearTerminal() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default: // linux, darwin, etc
		cmd = exec.Command("clear")
	}

	cmd.Stdout = os.Stdout
	cmd.Run()
}

func waitForEnter() {
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// normalizeString removes accents/diacritics and converts to lowercase for flexible search
// Example: "João" -> "joao", "Café" -> "cafe"
func normalizeString(s string) string {
	// Convert to lowercase first
	s = strings.ToLower(s)

	// Create transformer that removes combining marks (accents)
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	result, _, _ := transform.String(t, s)

	return result
}
