package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// DropMainDatabase para o banco principal (container), sem remover dados ou volumes.
func DropMainDatabase() {
	clearTerminal()
	fmt.Println("⚠ Esta ação irá parar o banco principal (container), mas não irá remover dados ou volumes.")
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
	if err := runDockerComposeStop("postgres"); err != nil {
		fmt.Println("Erro ao parar banco principal:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	} else {
		fmt.Println("Banco principal parado com sucesso!")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
}
