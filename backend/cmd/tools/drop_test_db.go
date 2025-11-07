package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Derruba banco de teste, removendo container, dados e volumes
func DropTestDatabase() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("⚠ Esta ação irá remover o banco de testes, todos os dados e volumes associados.")
	fmt.Print("Tem certeza que deseja continuar? (digite 'sim' para confirmar): ")
	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)
	if confirm != "sim" {
		fmt.Println("Operação cancelada.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	if err := runDockerComposeDownWithVolumes("postgres_test"); err != nil {
		fmt.Println("Erro ao derrubar banco de teste:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	} else {
		fmt.Println("Banco de teste removido com sucesso!")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
}
