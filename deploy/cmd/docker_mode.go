package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func dockerModeMenu() {
	for {
		clearTerminal()
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                   🐳 DOCKER MODE 🐳                                       ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                                                                            ║")
		fmt.Println("║                   🐳 ALL SERVICES 🐳                                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 11 - ▶️  Start all services                                                 ║")
		fmt.Println("║ 12 - ⏹️  Stop all services                                                  ║")
		fmt.Println("║ 13 - 🔄 Restart all services                                               ║")
		fmt.Println("║ 14 - 📊 View containers status                                             ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🎛️  DATABASE (PostgreSQL) 🎛️                                    ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 21 - ▶️  Start database                                                     ║")
		fmt.Println("║ 22 - ⏹️  Stop database                                                      ║")
		fmt.Println("║ 23 - 🔄 Restart database                                                   ║")
		fmt.Println("║ 24 - 🗑️  Clean database (remove container + volumes - DATA LOSS!)           ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🖥️  BACKEND (Go API) 🖥️                                         ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 25 - ▶️  Start backend                                                      ║")
		fmt.Println("║ 26 - ⏹️  Stop backend                                                       ║")
		fmt.Println("║ 27 - 🔄 Restart backend                                                    ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🌐 FRONTEND (Nginx) 🌐                                        ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 28 - ▶️  Start frontend                                                     ║")
		fmt.Println("║ 29 - ⏹️  Stop frontend                                                      ║")
		fmt.Println("║ 30 - 🔄 Restart frontend                                                   ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              📜 LOGS & MONITORING 📜                                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 31 - 📋 View all logs (follow)                                             ║")
		fmt.Println("║ 32 - 📊 View database logs                                                 ║")
		fmt.Println("║ 33 - 🔍 View backend logs                                                  ║")
		fmt.Println("║ 34 - 🌐 View frontend logs                                                 ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🧹 CLEANUP 🧹                                                 ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 50 - 💣 Stop & clean all (remove all containers + volumes - DATA LOSS!)    ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║              🔙 BACK                                                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 99 - 🔙 Back to main menu                                                  ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
		fmt.Print("\nOption: ")

		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "11":
			dockerStartAll()
		case "12":
			dockerStopAll()
		case "13":
			dockerRestartAll()
		case "14":
			dockerStatus()
		case "21":
			dockerStartDatabase()
		case "22":
			dockerStopDatabase()
		case "23":
			dockerRestartDatabase()
		case "24":
			dockerCleanDatabase()
		case "25":
			dockerStartBackend()
		case "26":
			dockerStopBackend()
		case "27":
			dockerRestartBackend()
		case "28":
			dockerStartFrontend()
		case "29":
			dockerStopFrontend()
		case "30":
			dockerRestartFrontend()
		case "31":
			dockerLogsAll()
		case "32":
			dockerLogsDatabase()
		case "33":
			dockerLogsBackend()
		case "34":
			dockerLogsFrontend()
		case "50":
			dockerCleanAll()
		case "99":
			return
		default:
			fmt.Println("❌ Invalid option.")
			time.Sleep(1 * time.Second)
		}
	}
}
