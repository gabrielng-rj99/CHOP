// Contracts-Manager/backend/cmd/tools/stop_server.go

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func stopServer() {
	clearTerminal()
	fmt.Println("=== Parar Servidor HTTP ===\n ")

	var cmd *exec.Cmd

	// Detecta o sistema operacional e usa o comando apropriado
	switch runtime.GOOS {
	case "windows":
		// No Windows, procura e mata processos Go rodando o servidor
		cmd = exec.Command("taskkill", "/F", "/IM", "go.exe")
	case "linux", "darwin":
		// No Linux/Mac, procura processos rodando na porta 3000
		pidCmd := exec.Command("bash", "-c", "lsof -ti:3000")
		output, err := pidCmd.Output()
		if err != nil || len(output) == 0 {
			fmt.Println("ℹ️  Nenhum servidor encontrado rodando na porta 3000")
			if !skipClearTerminal {
				fmt.Print("\nPressione ENTER para continuar...")
			}
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}

		pids := strings.TrimSpace(string(output))
		if pids == "" {
			fmt.Println("ℹ️  Nenhum servidor encontrado rodando na porta 3000")
			if !skipClearTerminal {
				fmt.Print("\nPressione ENTER para continuar...")
			}
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}

		fmt.Printf("🔍 Processos encontrados (PIDs): %s\n", pids)
		cmd = exec.Command("bash", "-c", fmt.Sprintf("kill -9 %s", pids))
	default:
		fmt.Printf("❌ Sistema operacional não suportado: %s\n", runtime.GOOS)
		if !skipClearTerminal {
			fmt.Print("\nPressione ENTER para continuar...")
		}
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	fmt.Println("🛑 Parando servidor HTTP...")

	err := cmd.Run()
	if err != nil {
		fmt.Printf("⚠️  Erro ao parar servidor: %v\n", err)
		fmt.Println("\nℹ️  O servidor pode já estar parado ou você pode precisar pará-lo manualmente com Ctrl+C")
	} else {
		fmt.Println("✅ Servidor HTTP parado com sucesso!")
	}

	if !skipClearTerminal {
		fmt.Print("\nPressione ENTER para continuar...")
	}
	bufio.NewReader(os.Stdin).ReadString('\n')
}
