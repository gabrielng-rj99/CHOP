package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func utilitiesMenu() {
	for {
		clearTerminal()
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                   🔧 UTILITIES 🔧                                         ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              ❤️  HEALTH CHECKS ❤️                                          ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 11 - ❤️  Database health check                                             ║")
		fmt.Println("║ 12 - 💚 Backend health check                                               ║")
		fmt.Println("║ 13 - 💙 Frontend health check                                              ║")
		fmt.Println("║ 14 - 🏥 Full system health check                                           ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🔍 DIAGNOSTICS 🔍                                            ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 21 - 📋 Validate DB separation (test vs main)                              ║")
		fmt.Println("║ 22 - 🔐 Validate configuration files                                       ║")
		fmt.Println("║ 23 - 📊 Full system diagnostics report                                     ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🧪 TESTING 🧪                                                 ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 31 - 🧪 Unit tests [PLACEHOLDER]                                           ║")
		fmt.Println("║ 32 - 🔗 Integration tests [PLACEHOLDER]                                    ║")
		fmt.Println("║ 33 - 🔒 Security tests [PLACEHOLDER]                                       ║")
		fmt.Println("║ 34 - 📊 Run all tests with coverage [PLACEHOLDER]                          ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              📊 REPORTS 📊                                                 ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 41 - 📈 Code coverage report [PLACEHOLDER]                                 ║")
		fmt.Println("║ 42 - 🔍 Performance metrics report [PLACEHOLDER]                           ║")
		fmt.Println("║ 43 - 📋 Database schema report [PLACEHOLDER]                               ║")
		fmt.Println("║ 44 - 🧮 System requirements report [PLACEHOLDER]                           ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🔙 BACK                                                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 00 - 🔙 Back to main menu                                                  ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
		fmt.Print("\nOption: ")

		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "11":
			healthCheckDatabase()
		case "12":
			healthCheckBackend()
		case "13":
			healthCheckFrontend()
		case "14":
			healthCheckFull()
		case "21":
			diagnosticsDBSeparation()
		case "22":
			diagnosticsConfiguration()
		case "23":
			diagnosticsFullSystem()
		case "31":
			testingUnit()
		case "32":
			testingIntegration()
		case "33":
			testingSecurity()
		case "34":
			testingAll()
		case "41":
			reportCodeCoverage()
		case "42":
			reportPerformance()
		case "43":
			reportDatabaseSchema()
		case "44":
			reportSystemRequirements()
		case "00", "0":
			return
		default:
			fmt.Println("❌ Invalid option.")
			time.Sleep(1 * time.Second)
		}
	}
}
