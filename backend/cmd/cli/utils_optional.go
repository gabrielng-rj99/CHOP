package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
