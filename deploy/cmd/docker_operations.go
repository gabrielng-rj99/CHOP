package main

import (
	"fmt"
	"time"
)

// ============================================================================
// DOCKER - ALL SERVICES
// ============================================================================

func dockerStartAll() {
	fmt.Println("\n▶️  Starting all services (docker-compose up -d)...")
	if err := runCommandInScripts("docker-compose", "up", "-d"); err != nil {
		printError(fmt.Sprintf("Failed to start services: %v", err))
	} else {
		printSuccess("All services started!")
		fmt.Println("  Frontend: http://localhost:8081")
		fmt.Println("  Backend:  http://localhost:3000")
		fmt.Println("  Database: localhost:5432")
	}
	waitForEnter()
}

func dockerStopAll() {
	fmt.Println("\n⏹️  Stopping all services (docker-compose down)...")
	if err := runCommandInScripts("docker-compose", "down"); err != nil {
		printError(fmt.Sprintf("Failed to stop services: %v", err))
	} else {
		printSuccess("All services stopped!")
	}
	waitForEnter()
}

func dockerRestartAll() {
	fmt.Println("\n🔄 Restarting all services...")
	dockerStopAll()
	time.Sleep(2 * time.Second)
	dockerStartAll()
}

func dockerStatus() {
	fmt.Println("\n📊 Container status (docker-compose ps):")
	fmt.Println()
	runCommandInScripts("docker-compose", "ps")
	waitForEnter()
}

// ============================================================================
// DOCKER - DATABASE
// ============================================================================

func dockerStartDatabase() {
	fmt.Println("\n▶️  Starting PostgreSQL Database (docker-compose up -d postgres)...")
	if err := runCommandInScripts("docker-compose", "up", "-d", "postgres"); err != nil {
		printError(fmt.Sprintf("Failed to start database: %v", err))
	} else {
		printSuccess("PostgreSQL Database started!")
		fmt.Println("  Database: localhost:5432")
	}
	waitForEnter()
}

func dockerStopDatabase() {
	fmt.Println("\n⏹️  Stopping PostgreSQL Database (docker-compose stop postgres)...")
	if err := runCommandInScripts("docker-compose", "stop", "postgres"); err != nil {
		printError(fmt.Sprintf("Failed to stop database: %v", err))
	} else {
		printSuccess("PostgreSQL Database stopped!")
	}
	waitForEnter()
}

func dockerRestartDatabase() {
	fmt.Println("\n🔄 Restarting PostgreSQL Database...")
	if err := runCommandInScripts("docker-compose", "restart", "postgres"); err != nil {
		printError(fmt.Sprintf("Failed to restart database: %v", err))
	} else {
		printSuccess("PostgreSQL Database restarted!")
	}
	waitForEnter()
}

func dockerCleanDatabase() {
	fmt.Println("\n⚠️  This will PERMANENTLY DELETE all database data!")
	if !confirmAction("Type 'yes' to confirm: ") {
		printWarning("Cancelled.")
		waitForEnter()
		return
	}

	fmt.Println("🗑️  Cleaning database (removing container + volumes)...")
	if err := runCommandInScripts("docker-compose", "down", "-v", "--remove-orphans"); err != nil {
		printError(fmt.Sprintf("Failed to clean database: %v", err))
	} else {
		printSuccess("Database cleaned!")
		fmt.Println("\nStarting fresh database...")
		dockerStartDatabase()
	}
	waitForEnter()
}

// ============================================================================
// DOCKER - BACKEND
// ============================================================================

func dockerStartBackend() {
	fmt.Println("\n▶️  Starting Backend API (docker-compose up -d backend)...")
	if err := runCommandInScripts("docker-compose", "up", "-d", "backend"); err != nil {
		printError(fmt.Sprintf("Failed to start backend: %v", err))
	} else {
		printSuccess("Backend API started!")
		fmt.Println("  Backend: http://localhost:3000")
	}
	waitForEnter()
}

func dockerStopBackend() {
	fmt.Println("\n⏹️  Stopping Backend API (docker-compose stop backend)...")
	if err := runCommandInScripts("docker-compose", "stop", "backend"); err != nil {
		printError(fmt.Sprintf("Failed to stop backend: %v", err))
	} else {
		printSuccess("Backend API stopped!")
	}
	waitForEnter()
}

func dockerRestartBackend() {
	fmt.Println("\n🔄 Restarting Backend API...")
	if err := runCommandInScripts("docker-compose", "restart", "backend"); err != nil {
		printError(fmt.Sprintf("Failed to restart backend: %v", err))
	} else {
		printSuccess("Backend API restarted!")
	}
	waitForEnter()
}

// ============================================================================
// DOCKER - FRONTEND
// ============================================================================

func dockerStartFrontend() {
	fmt.Println("\n▶️  Starting Frontend (Nginx) (docker-compose up -d frontend)...")
	if err := runCommandInScripts("docker-compose", "up", "-d", "frontend"); err != nil {
		printError(fmt.Sprintf("Failed to start frontend: %v", err))
	} else {
		printSuccess("Frontend (Nginx) started!")
		fmt.Println("  Frontend: http://localhost:8081")
	}
	waitForEnter()
}

func dockerStopFrontend() {
	fmt.Println("\n⏹️  Stopping Frontend (Nginx) (docker-compose stop frontend)...")
	if err := runCommandInScripts("docker-compose", "stop", "frontend"); err != nil {
		printError(fmt.Sprintf("Failed to stop frontend: %v", err))
	} else {
		printSuccess("Frontend (Nginx) stopped!")
	}
	waitForEnter()
}

func dockerRestartFrontend() {
	fmt.Println("\n🔄 Restarting Frontend (Nginx)...")
	if err := runCommandInScripts("docker-compose", "restart", "frontend"); err != nil {
		printError(fmt.Sprintf("Failed to restart frontend: %v", err))
	} else {
		printSuccess("Frontend (Nginx) restarted!")
	}
	waitForEnter()
}

// ============================================================================
// DOCKER - LOGS
// ============================================================================

func dockerLogsAll() {
	fmt.Println("\n📋 Displaying all logs (press Ctrl+C to exit)...")
	fmt.Println()
	runCommandInScripts("docker-compose", "logs", "-f")
	waitForEnter()
}

func dockerLogsDatabase() {
	fmt.Println("\n📊 Displaying PostgreSQL Database logs (press Ctrl+C to exit)...")
	fmt.Println()
	runCommandInScripts("docker-compose", "logs", "-f", "postgres")
	waitForEnter()
}

func dockerLogsBackend() {
	fmt.Println("\n🔍 Displaying Backend API logs (press Ctrl+C to exit)...")
	fmt.Println()
	runCommandInScripts("docker-compose", "logs", "-f", "backend")
	waitForEnter()
}

func dockerLogsFrontend() {
	fmt.Println("\n🌐 Displaying Frontend (Nginx) logs (press Ctrl+C to exit)...")
	fmt.Println()
	runCommandInScripts("docker-compose", "logs", "-f", "frontend")
	waitForEnter()
}

func dockerCleanAll() {
	fmt.Println("\n⚠️  This will stop all services and remove all containers + volumes!")
	if !confirmAction("Type 'yes' to confirm: ") {
		printWarning("Cancelled.")
		waitForEnter()
		return
	}

	fmt.Println("💣 Stopping and cleaning all services...")
	if err := runCommandInScripts("docker-compose", "down", "-v", "--remove-orphans"); err != nil {
		printError(fmt.Sprintf("Failed to clean all: %v", err))
	} else {
		printSuccess("All services stopped and cleaned!")
	}
	waitForEnter()
}
