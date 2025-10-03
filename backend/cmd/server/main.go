// Licenses-Manager/backend/cmd/server/main.go

package main

import (
	"fmt"
	"log"

	"Licenses-Manager/backend/database"
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
)

func main() {
	// ... (ETAPA 1 permanece a mesma) ...
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatalf("Erro ao conectar ao banco de dados: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Erro ao fechar a conexão com o banco de dados: %v", err)
		}
	}()
	fmt.Println("--- Conexão com o banco de dados estabelecida com sucesso! ---")
	companyStore := store.NewCompanyStore(db)

	// --- ETAPA 2: CREATE ---
	fmt.Println("\n--- Testando: CREATE ---")
	novaEmpresa := domain.Company{
		Name: "Sapatos Modernos Ltda",
		CNPJ: "11.222.333/0001-44",
	}
	newID, err := companyStore.CreateCompany(novaEmpresa)
	if err != nil {
		log.Fatalf("Erro ao criar empresa: %v", err)
	}
	fmt.Printf("Empresa criada com sucesso! ID: %s\n", newID)

	// Verificando o estado inicial (deve estar ativa)
	empresaCriada, err := companyStore.GetCompanyByID(newID)
	if err != nil {
		log.Fatalf("Erro ao buscar empresa recém-criada: %v", err)
	}
	if empresaCriada == nil {
		log.Fatalf("ERRO: A empresa não foi encontrada após a criação.")
	}
	if empresaCriada.ArchivedAt == nil {
		fmt.Println("Verificação -> Status: Ativa")
	} else {
		fmt.Println("Verificação -> Status: Arquivada")
	}

	// --- ETAPA 3: ARCHIVE ---
	fmt.Println("\n--- Testando: ARCHIVE ---")
	err = companyStore.ArchiveCompany(newID)
	if err != nil {
		log.Fatalf("Erro ao arquivar empresa: %v", err)
	}
	fmt.Println("Empresa arquivada com sucesso!")

	// Verificando se foi arquivada
	empresaArquivada, err := companyStore.GetCompanyByID(newID)
	// CORREÇÃO: Verificamos o erro ANTES de usar a variável
	if err != nil {
		log.Fatalf("Erro ao buscar empresa após arquivamento: %v", err)
	}
	if empresaArquivada == nil {
		log.Fatalf("ERRO: A empresa não foi encontrada após o arquivamento.")
	}
	if empresaArquivada.ArchivedAt != nil {
		fmt.Printf("Verificação -> Status: Arquivada em %s\n", empresaArquivada.ArchivedAt.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("ERRO: Empresa deveria estar arquivada, mas não está.")
	}

	// --- ETAPA 4: UNARCHIVE ---
	fmt.Println("\n--- Testando: UNARCHIVE ---")
	err = companyStore.UnarchiveCompany(newID)
	if err != nil {
		log.Fatalf("Erro ao desarquivar empresa: %v", err)
	}
	fmt.Println("Empresa desarquivada com sucesso!")

	// Verificando se voltou a estar ativa
	empresaDesarquivada, err := companyStore.GetCompanyByID(newID)
	// CORREÇÃO: Verificamos o erro
	if err != nil {
		log.Fatalf("Erro ao buscar empresa após desarquivamento: %v", err)
	}
	if empresaDesarquivada == nil {
		log.Fatalf("ERRO: A empresa não foi encontrada após o desarquivamento.")
	}
	if empresaDesarquivada.ArchivedAt == nil {
		fmt.Println("Verificação -> Status: Ativa novamente")
	} else {
		fmt.Println("ERRO: Empresa deveria estar ativa, mas não está.")
	}

	// --- ETAPA 5: DELETE PERMANENTE ---
	fmt.Println("\n--- Testando: DELETE PERMANENTE (LGPD) ---")
	err = companyStore.DeleteCompanyPermanently(newID)
	if err != nil {
		log.Fatalf("Erro ao deletar permanentemente a empresa: %v", err)
	}
	fmt.Println("Empresa deletada permanentemente com sucesso!")

	// Verificando se foi realmente deletada
	empresaDeletada, err := companyStore.GetCompanyByID(newID)
	// CORREÇÃO: Verificamos o erro
	if err != nil {
		log.Fatalf("Erro ao verificar deleção: %v", err)
	}
	if empresaDeletada == nil {
		fmt.Println("Verificação -> Empresa não encontrada, como esperado.")
	} else {
		fmt.Println("ERRO: Empresa ainda existe no banco após ser deletada permanentemente.")
	}

	fmt.Println("\n--- Teste do ciclo de vida da empresa concluído com sucesso! ---")
}
