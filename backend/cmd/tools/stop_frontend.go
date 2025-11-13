// Contracts-Manager/backend/cmd/tools/stop_frontend.go

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func stopFrontend() {
	clearTerminal()
	fmt.Println("=== Parar Frontend ===\n ")

	var cmd *exec.Cmd

	// Detecta o sistema operacional e usa o comando apropriado
	switch runtime.GOOS {
	case "windows":
		// No Windows, procura e mata processos Node rodando Vite
		cmd = exec.Command("taskkill", "/F", "/IM", "node.exe")
	case "linux", "darwin":
		// No Linux/Mac, procura processos rodando na porta 8080
		pidCmd := exec.Command("sh", "-c", "lsof -ti:8080")
		output, err := pidCmd.Output()
		if err != nil || len(output) == 0 {
			fmt.Println("ℹ️  Nenhum frontend encontrado rodando na porta 8080")
			fmt.Print("\nPressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}

		pids := strings.TrimSpace(string(output))
		if pids == "" {
			fmt.Println("ℹ️  Nenhum frontend encontrado rodando na porta 8080")
			fmt.Print("\nPressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}

		fmt.Printf("🔍 Processos encontrados (PIDs): %s\n", pids)
		cmd = exec.Command("sh", "-c", fmt.Sprintf("kill -9 %s", pids))
	default:
		fmt.Printf("❌ Sistema operacional não suportado: %s\n", runtime.GOOS)
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	fmt.Println("🛑 Parando frontend...")

	err := cmd.Run()
	if err != nil {
		fmt.Printf("⚠️  Erro ao parar frontend: %v\n", err)
		fmt.Println("\nℹ️  O frontend pode já estar parado ou você pode precisar pará-lo manualmente com Ctrl+C")
	} else {
		fmt.Println("✅ Frontend parado com sucesso!")
	}

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
