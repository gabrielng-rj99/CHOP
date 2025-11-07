package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// DropMainDatabaseWithVolumes remove o banco principal, dados e volumes (ação destrutiva)
func DropMainDatabaseWithVolumes() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("⚠ ATENÇÃO: Esta ação irá REMOVER o banco principal, TODOS os dados e volumes associados.")
	fmt.Println("É altamente recomendado exportar um backup antes de continuar. (Backup: em desenvolvimento)")
	fmt.Print("Tem certeza que deseja continuar? (digite 'DESTRUIR' para confirmar): ")
	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)
	if confirm != "DESTRUIR" {
		fmt.Println("Operação cancelada.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	if err := runDockerComposeDownWithVolumes("postgres"); err != nil {
		fmt.Println("Erro ao remover banco principal:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	} else {
		fmt.Println("Banco principal removido com sucesso!")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
}
