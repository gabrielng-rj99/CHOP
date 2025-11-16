// Contracts-Manager/backend/cmd/tools/check_services.go

package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func checkServices() {
	clearTerminal()
	fmt.Println("=== Diagnóstico de Serviços ===\n ")

	// Verifica servidor HTTP (porta 3000)
	fmt.Println("🔍 Verificando Servidor HTTP (porta 3000)...")
	serverRunning := checkPort(3000)
	serverHealthy := false

	if serverRunning {
		fmt.Println("   ✅ Processo detectado na porta 3000")

		// Tenta acessar o health check
		serverHealthy = checkHealthEndpoint("http://localhost:3000/health")
		if serverHealthy {
			fmt.Println("   ✅ Health check respondendo corretamente")
		} else {
			fmt.Println("   ⚠️  Health check não está respondendo")
		}
	} else {
		fmt.Println("   ❌ Nenhum processo rodando na porta 3000")
		fmt.Println("   💡 Use a opção 12 para iniciar o servidor")
	}

	fmt.Println()

	// Verifica frontend (porta 8080)
	fmt.Println("🔍 Verificando Frontend (porta 8080)...")
	frontendRunning := checkPort(8080)

	if frontendRunning {
		fmt.Println("   ✅ Processo detectado na porta 8080")

		// Tenta acessar a página principal
		frontendHealthy := checkFrontendEndpoint("http://localhost:8080")
		if frontendHealthy {
			fmt.Println("   ✅ Frontend acessível")
		} else {
			fmt.Println("   ⚠️  Frontend pode estar iniciando...")
		}
	} else {
		fmt.Println("   ❌ Nenhum processo rodando na porta 8080")
		fmt.Println("   💡 Use a opção 14 para iniciar o frontend")
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("📊 Resumo:")

	if serverRunning && serverHealthy {
		fmt.Println("   ✅ Servidor HTTP: Operacional")
	} else if serverRunning {
		fmt.Println("   ⚠️  Servidor HTTP: Rodando mas com problemas")
	} else {
		fmt.Println("   ❌ Servidor HTTP: Parado")
	}

	if frontendRunning {
		fmt.Println("   ✅ Frontend: Operacional")
	} else {
		fmt.Println("   ❌ Frontend: Parado")
	}

	fmt.Println()
	if serverRunning && frontendRunning && serverHealthy {
		fmt.Println("🎉 Sistema completo está rodando!")
		fmt.Println("   Acesse: http://localhost:8080")
	} else {
		fmt.Println("⚠️  Alguns serviços não estão rodando")
		if !serverRunning {
			fmt.Println("   → Inicie o servidor (opção 12)")
		}
		if !frontendRunning {
			fmt.Println("   → Inicie o frontend (opção 13)")
		}
	}

	if !skipClearTerminal {
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}

}

// checkPort verifica se há algum processo rodando na porta especificada
func checkPort(port int) bool {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("netstat", "-ano")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		portStr := fmt.Sprintf(":%d", port)
		return strings.Contains(string(output), portStr)
	case "linux", "darwin":
		cmd := exec.Command("sh", "-c", fmt.Sprintf("lsof -ti:%d", port))
		output, err := cmd.Output()
		if err != nil || len(output) == 0 {
			return false
		}
		pids := strings.TrimSpace(string(output))
		return pids != ""
	default:
		return false
	}
}

// checkHealthEndpoint verifica se o endpoint de health check está respondendo
func checkHealthEndpoint(url string) bool {
	client := http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// checkFrontendEndpoint verifica se o frontend está acessível
func checkFrontendEndpoint(url string) bool {
	client := http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
