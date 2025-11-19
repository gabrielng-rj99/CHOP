package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func monolithModeMenu() {
	for {
		clearTerminal()
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                   🖥️  MONOLITH MODE 🖥️                                     ║")
		fmt.Println("║              (Services running directly on host machine)                  ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                                                                            ║")
		fmt.Println("║                   🖥️  ALL SERVICES 🖥️                                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 11 - ▶️  Start all services                                                 ║")
		fmt.Println("║ 12 - ⏹️  Stop all services                                                  ║")
		fmt.Println("║ 13 - 🔄 Restart all services                                               ║")
		fmt.Println("║ 14 - 📊 View services status                                               ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🗄️  DATABASE (PostgreSQL) 🗄️                                    ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 21 - ▶️  Start database (local PostgreSQL)                                  ║")
		fmt.Println("║ 22 - ⏹️  Stop database                                                      ║")
		fmt.Println("║ 23 - 🔄 Restart database                                                   ║")
		fmt.Println("║ 24 - 📊 Check database status                                              ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🖥️  BACKEND (Go API) 🖥️                                         ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 25 - ▶️  Start backend (go run ./cmd/api)                                   ║")
		fmt.Println("║ 26 - ⏹️  Stop backend                                                       ║")
		fmt.Println("║ 27 - 🔄 Restart backend                                                    ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🌐 FRONTEND (Node.js) 🌐                                      ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 28 - ▶️  Start frontend (npm run dev)                                       ║")
		fmt.Println("║ 29 - ⏹️  Stop frontend                                                      ║")
		fmt.Println("║ 30 - 🔄 Restart frontend                                                   ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              📜 LOGS & MONITORING 📜                                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 31 - 📋 View all service logs (follow)                                     ║")
		fmt.Println("║ 32 - 📊 View database logs                                                 ║")
		fmt.Println("║ 33 - 🔍 View backend logs                                                  ║")
		fmt.Println("║ 34 - 🌐 View frontend logs                                                 ║")
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
			monolithStartAll()
		case "12":
			monolithStopAll()
		case "13":
			monolithRestartAll()
		case "14":
			monolithStatus()
		case "21":
			monolithStartDatabase()
		case "22":
			monolithStopDatabase()
		case "23":
			monolithRestartDatabase()
		case "24":
			monolithDatabaseStatus()
		case "25":
			monolithStartBackend()
		case "26":
			monolithStopBackend()
		case "27":
			monolithRestartBackend()
		case "28":
			monolithStartFrontend()
		case "29":
			monolithStopFrontend()
		case "30":
			monolithRestartFrontend()
		case "31":
			monolithLogsAll()
		case "32":
			monolithLogsDatabase()
		case "33":
			monolithLogsBackend()
		case "34":
			monolithLogsFrontend()
		case "00", "0":
			return
		default:
			fmt.Println("❌ Invalid option.")
			time.Sleep(1 * time.Second)
		}
	}
}
