package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// clearTerminal clears the terminal screen
func clearTerminal() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// waitForEnter waits for user to press Enter
func waitForEnter() {
	fmt.Print("\n👉 Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// getProjectRoot finds the project root directory
func getProjectRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		ex, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("cannot determine project root")
		}
		currentDir = filepath.Dir(ex)
	}

	for i := 0; i < 10; i++ {
		deployPath := filepath.Join(currentDir, "deploy")
		if _, err := os.Stat(deployPath); err == nil {
			return currentDir, nil
		}

		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			break
		}
		currentDir = parent
	}

	return "", fmt.Errorf("project root not found - deploy directory not located")
}

// runCommandInScripts runs a command in the scripts directory
func runCommandInScripts(args ...string) error {
	projectRoot, err := getProjectRoot()
	if err != nil {
		fmt.Printf("❌ Error finding project root: %v\n", err)
		return err
	}
	scriptsDir := filepath.Join(projectRoot, "deploy", "scripts")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = scriptsDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runCommand runs a command from a specific directory
func runCommand(dir string, args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runCommandSilent runs a command and returns output
func runCommandSilent(dir string, args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// runBackgroundCommand runs a command in background and returns the process
func runBackgroundCommand(dir string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	err := cmd.Start()
	return cmd, err
}

// printHeader prints a formatted header
func printHeader(title string) {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║ %-74s ║\n", title)
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// printSection prints a formatted section title
func printSection(title string) {
	fmt.Printf("\n%s\n", title)
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")
}

// printSuccess prints a success message
func printSuccess(message string) {
	fmt.Printf("✅ %s\n", message)
}

// printError prints an error message
func printError(message string) {
	fmt.Printf("❌ %s\n", message)
}

// printWarning prints a warning message
func printWarning(message string) {
	fmt.Printf("⚠️  %s\n", message)
}

// printInfo prints an info message
func printInfo(message string) {
	fmt.Printf("ℹ️  %s\n", message)
}

// printLoading prints a loading message
func printLoading(message string) {
	fmt.Printf("⏳ %s\n", message)
}

// confirmAction asks user for confirmation
func confirmAction(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return input == "yes\n" || input == "y\n"
}

// inputPrompt reads user input with a prompt
func inputPrompt(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return input[:len(input)-1] // Remove newline
}
