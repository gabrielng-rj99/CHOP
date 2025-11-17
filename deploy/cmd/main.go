package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	for {
		clearTerminal()
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                   🚀 CONTRACT MANAGER DEPLOY 🚀                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
		fmt.Println("")
		fmt.Println("Select deployment mode:")
		fmt.Println("")
		fmt.Println("  1 - 🐳 Docker Mode       (containerized services)")
		fmt.Println("  2 - 🖥️  Monolith Mode     (services on host machine)")
		fmt.Println("  3 - 🔧 Utilities        (health, diagnostics, tests, reports)")
		fmt.Println("  0 - 🚪 Exit")
		fmt.Println("")
		fmt.Print("Option: ")

		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			dockerModeMenu()
		case "2":
			monolithModeMenu()
		case "3":
			utilitiesMenu()
		case "0":
			fmt.Println("👋 Exiting...")
			time.Sleep(500 * time.Millisecond)
			clearTerminal()
			return
		default:
			fmt.Println("❌ Invalid option.")
			time.Sleep(1 * time.Second)
		}
	}
}
