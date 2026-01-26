//go:build disabled
// +build disabled

/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// DISABLED: This file contains integration tests that require store constructors
// from multiple subpackages, which causes import cycles. These tests should be
// refactored into their respective subpackage test suites.
package repository

import (
	"Open-Generic-Hub/backend/domain"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestClientRelationshipIntegrity testa integridade de relacionamentos
func TestClientRelationshipIntegrity(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)
	subClientStore := NewAffiliateStore(db)
	categoryStore := NewCategoryStore(db)
	subcategoryStore := NewSubcategoryStore(db)
	contractStore := NewContractStore(db)

	t.Run("affiliate referenciando cliente inexistente", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		fakeClientID := uuid.New().String()
		affiliate := domain.Affiliate{
			Name:     "Test Affiliate",
			ClientID: fakeClientID,
			Status:   "ativo",
		}

		_, err := subClientStore.CreateAffiliate(affiliate)
		if err == nil {
			t.Error("Esperava erro ao criar afiliado com client_id inexistente")
		}

		if err != nil && !strings.Contains(err.Error(), "foreign key") && !strings.Contains(err.Error(), "violates") && !strings.Contains(err.Error(), "not found") {
			t.Logf("Erro obtido (pode ser válido): %v", err)
		}
	})

	t.Run("affiliate após delete do cliente", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		client := domain.Client{
			Name:   "Client To Delete",
			Status: "ativo",
		}

		clientID, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		affiliate := domain.Affiliate{
			Name:     "Affiliate Of Client",
			ClientID: clientID,
			Status:   "ativo",
		}

		depID, err := subClientStore.CreateAffiliate(affiliate)
		if err != nil {
			t.Fatalf("Failed to create affiliate: %v", err)
		}

		err = clientStore.ArchiveClient(clientID)
		if err != nil {
			t.Logf("Archive client result: %v", err)
		}

		fetchedDep, err := subClientStore.GetAffiliateByID(depID)
		if err != nil {
			t.Fatalf("Failed to fetch affiliate: %v", err)
		}

		if fetchedDep.ClientID != clientID {
			t.Error("Affiliate deveria ainda referenciar o cliente")
		}
	})

	t.Run("contrato com subcategory_id inválido", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		client := domain.Client{
			Name:   "Test Client",
			Status: "ativo",
		}
		clientID, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		fakeSubcategoryID := uuid.New().String()
		contract := domain.Contract{
			Model:         "Test Model",
			ItemKey:       "KEY-123",
			StartDate:     timePtr(time.Now()),
			EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
			SubcategoryID: fakeSubcategoryID,
			ClientID:      clientID,
		}

		_, err = contractStore.CreateContract(contract)
		if err == nil {
			t.Error("Esperava erro ao criar contrato com subcategory_id inexistente")
		}
	})

	t.Run("contrato após archive do cliente", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		client := domain.Client{
			Name:   "Client To Archive",
			Status: "ativo",
		}
		clientID, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		category := domain.Category{Name: "Test Category"}
		catID, err := categoryStore.CreateCategory(category)
		if err != nil {
			t.Fatalf("Failed to create category: %v", err)
		}

		line := domain.Subcategory{
			Name:       "Test Subcategory",
			CategoryID: catID,
		}
		subcategoryID, err := subcategoryStore.CreateSubcategory(line)
		if err != nil {
			t.Fatalf("Failed to create line: %v", err)
		}

		contract := domain.Contract{
			Model:         "Test Model",
			ItemKey:       "KEY-123",
			StartDate:     timePtr(time.Now()),
			EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
			SubcategoryID: subcategoryID,
			ClientID:      clientID,
		}
		contractID, err := contractStore.CreateContract(contract)
		if err != nil {
			t.Fatalf("Failed to create contract: %v", err)
		}

		err = clientStore.ArchiveClient(clientID)
		if err != nil {
			t.Logf("Archive client result: %v", err)
		}

		fetchedContract, err := contractStore.GetContractByID(contractID)
		if err != nil {
			t.Fatalf("Failed to fetch contract: %v", err)
		}

		if fetchedContract.ClientID != clientID {
			t.Error("Contract deveria ainda referenciar o cliente arquivado")
		}
	})
}

// TestConcurrentClientCreation testa race conditions
func TestConcurrentClientCreation(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	t.Run("dois clientes com mesmo nome simultaneamente", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		var wg sync.WaitGroup
		errors := make(chan error, 2)
		ids := make(chan string, 2)

		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				client := domain.Client{
					Name:   "Concurrent Test Client",
					Status: "ativo",
				}

				id, err := clientStore.CreateClient(client)
				if err != nil {
					errors <- err
				} else {
					ids <- id
				}
			}()
		}

		wg.Wait()
		close(errors)
		close(ids)

		var errCount int
		for err := range errors {
			if err != nil {
				errCount++
			}
		}

		var createdIDs []string
		for id := range ids {
			createdIDs = append(createdIDs, id)
		}

		if len(createdIDs) == 2 {
			t.Log("Ambos os clientes foram criados com sucesso (nome não é único quando sem registration_id)")
		}
	})

	t.Run("race condition em verificação de CNPJ único", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		cnpj := "45.723.174/0001-10"
		var wg sync.WaitGroup
		errors := make(chan error, 5)
		successes := make(chan string, 5)

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				client := domain.Client{
					Name:           "Concurrent CNPJ Test",
					Status:         "ativo",
					RegistrationID: &cnpj,
				}

				id, err := clientStore.CreateClient(client)
				if err != nil {
					errors <- err
				} else {
					successes <- id
				}
			}(i)
		}

		wg.Wait()
		close(errors)
		close(successes)

		var successCount int
		for range successes {
			successCount++
		}

		var errorCount int
		for range errors {
			errorCount++
		}

		if successCount != 1 {
			t.Errorf("Esperava exatamente 1 sucesso, obteve %d", successCount)
		}

		if errorCount != 4 {
			t.Logf("Esperava 4 erros, obteve %d (pode haver race condition)", errorCount)
		}
	})
}

// TestEmailEdgeCases testa casos extremos de email
func TestEmailEdgeCases(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	t.Run("email com 254 caracteres", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		local := strings.Repeat("a", 64)
		domainPart := strings.Repeat("b", 185)
		email := local + "@" + domainPart + ".com"

		if len(email) != 254 {
			t.Fatalf("Email deveria ter 254 chars, tem %d", len(email))
		}

		client := domain.Client{
			Name:   "Test Client",
			Status: "ativo",
			Email:  &email,
		}

		_, err := clientStore.CreateClient(client)
		if err != nil && strings.Contains(err.Error(), "254") {
			t.Errorf("Não deveria falhar para email com 254 caracteres: %v", err)
		}
	})

	t.Run("email com 255 caracteres deve falhar na validação", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		email := strings.Repeat("a", 255) + "@example.com"

		client := domain.Client{
			Name:   "Test Client",
			Status: "ativo",
			Email:  &email,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro para email com 255+ caracteres")
		}
	})
}

// TestUnicodeAndEmojisInDatabase testa Unicode e emojis persistidos no banco
func TestUnicodeAndEmojisInDatabase(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	t.Run("cliente com nome contendo emojis", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		name := "Empresa Tecnologia 🚀💻"
		client := domain.Client{
			Name:   name,
			Status: "ativo",
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client with emojis: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Name != name {
			t.Errorf("Nome com emojis não foi preservado. Esperava '%s', obteve '%s'", name, fetched.Name)
		}
	})

	t.Run("cliente com notas multilíngues", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		notes := "Cliente Internacional 🌍\n日本語対応 - Japanese Support\nРусский - Russian\nالعربية - Arabic\n中文 - Chinese"
		client := domain.Client{
			Name:   "International Client",
			Status: "ativo",
			Notes:  &notes,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client with multilingual notes: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Notes == nil || *fetched.Notes != notes {
			t.Error("Notas multilíngues não foram preservadas corretamente")
		}
	})

	t.Run("endereço com caracteres especiais brasileiros", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		address := "Rua José de Alencar, 123 - Apto 45-B (Edifício São João) - Bairro Açúcar"
		client := domain.Client{
			Name:    "Test Client",
			Status:  "ativo",
			Address: &address,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client with special characters: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Address == nil || *fetched.Address != address {
			t.Error("Endereço com caracteres especiais não foi preservado")
		}
	})

	t.Run("tags com vírgulas e caracteres especiais", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		tags := "vip,prioritário,ação-urgente,follow-up"
		client := domain.Client{
			Name:   "Test Client",
			Status: "ativo",
			Tags:   &tags,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client with tags: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Tags == nil || *fetched.Tags != tags {
			t.Error("Tags não foram preservadas corretamente")
		}
	})
}

// TestDateValidationEdgeCases testa edge cases de datas
func TestDateValidationEdgeCases(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)
	categoryStore := NewCategoryStore(db)
	subcategoryStore := NewSubcategoryStore(db)
	contractStore := NewContractStore(db)

	t.Run("birthdate no futuro deve falhar", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		futureDate := time.Now().AddDate(1, 0, 0)
		client := domain.Client{
			Name:      "Test Client",
			Status:    "ativo",
			BirthDate: &futureDate,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro ao criar cliente com BirthDate no futuro")
		}

		if err != nil && !strings.Contains(err.Error(), "futuro") {
			t.Errorf("Mensagem de erro inesperada: %v", err)
		}
	})

	t.Run("birthdate muito antiga deve falhar", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		ancientDate := time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
		client := domain.Client{
			Name:      "Test Client",
			Status:    "ativo",
			BirthDate: &ancientDate,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro ao criar cliente com BirthDate anterior a 1900")
		}

		if err != nil && !strings.Contains(err.Error(), "1900") {
			t.Errorf("Mensagem de erro inesperada: %v", err)
		}
	})

	t.Run("birthdate válida em 1900", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		validDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
		client := domain.Client{
			Name:      "Test Client Valid 1900",
			Status:    "ativo",
			BirthDate: &validDate,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Errorf("Não esperava erro para BirthDate em 1900: %v", err)
		}

		if id == "" {
			t.Error("ID deveria ser retornado para cliente válido")
		}
	})

	t.Run("next action date recente no passado deve ser válido", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		pastDate := time.Now().AddDate(0, -6, 0) // 6 meses atrás
		client := domain.Client{
			Name:           "Test Client Recent Past",
			Status:         "ativo",
			NextActionDate: &pastDate,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Errorf("Não esperava erro para NextActionDate 6 meses no passado: %v", err)
		}

		if id == "" {
			t.Error("ID deveria ser retornado para cliente válido")
		}
	})

	t.Run("next action date mais de 1 ano no passado deve falhar", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		pastDate := time.Now().AddDate(-2, 0, 0) // 2 anos atrás
		client := domain.Client{
			Name:           "Test Client Far Past",
			Status:         "ativo",
			NextActionDate: &pastDate,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro para NextActionDate mais de 1 ano no passado")
		}

		if err != nil && !strings.Contains(err.Error(), "1 ano no passado") {
			t.Errorf("Mensagem de erro inesperada: %v", err)
		}
	})

	t.Run("next action date muito no futuro deve falhar", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		futureDate := time.Now().AddDate(20, 0, 0) // 20 anos no futuro
		client := domain.Client{
			Name:           "Test Client Far Future",
			Status:         "ativo",
			NextActionDate: &futureDate,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro para NextActionDate mais de 10 anos no futuro")
		}

		if err != nil && !strings.Contains(err.Error(), "10 anos no futuro") {
			t.Errorf("Mensagem de erro inesperada: %v", err)
		}
	})

	t.Run("next action date válido - 5 anos no futuro", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		futureDate := time.Now().AddDate(5, 0, 0) // 5 anos no futuro
		client := domain.Client{
			Name:           "Test Client Valid Future",
			Status:         "ativo",
			NextActionDate: &futureDate,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Errorf("Não esperava erro para NextActionDate 5 anos no futuro: %v", err)
		}

		if id == "" {
			t.Error("ID deveria ser retornado para cliente válido")
		}
	})

	t.Run("contract com start_date após end_date", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		client := domain.Client{
			Name:   "Test Client",
			Status: "ativo",
		}
		clientID, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		category := domain.Category{Name: "Test Category"}
		catID, err := categoryStore.CreateCategory(category)
		if err != nil {
			t.Fatalf("Failed to create category: %v", err)
		}

		line := domain.Subcategory{
			Name:       "Test Subcategory",
			CategoryID: catID,
		}
		subcategoryID, err := subcategoryStore.CreateSubcategory(line)
		if err != nil {
			t.Fatalf("Failed to create line: %v", err)
		}

		contract := domain.Contract{
			Model:         "Invalid Date Contract",
			ItemKey:       "KEY-123",
			StartDate:     timePtr(time.Now().AddDate(1, 0, 0)),
			EndDate:       timePtr(time.Now()),
			SubcategoryID: subcategoryID,
			ClientID:      clientID,
		}

		_, err = contractStore.CreateContract(contract)
		if err != nil {
			t.Logf("Create failed with invalid dates (good): %v", err)
		} else {
			t.Log("Contract com StartDate > EndDate foi aceito (pode precisar validação)")
		}
	})

	t.Run("notes com mais de 50000 caracteres deve falhar", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		longNotes := strings.Repeat("a", 50001)
		client := domain.Client{
			Name:   "Test Client Long Notes",
			Status: "ativo",
			Notes:  &longNotes,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro para notes com mais de 50000 caracteres")
		}

		if err != nil && !strings.Contains(err.Error(), "50.000") {
			t.Errorf("Mensagem de erro inesperada: %v", err)
		}
	})

	t.Run("notes com exatamente 50000 caracteres deve ser válido", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		validNotes := strings.Repeat("a", 50000)
		client := domain.Client{
			Name:   "Test Client Valid Notes",
			Status: "ativo",
			Notes:  &validNotes,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Errorf("Não esperava erro para notes com 50000 caracteres: %v", err)
		}

		if id == "" {
			t.Error("ID deveria ser retornado para cliente válido")
		}
	})

	t.Run("documents com mais de 10000 caracteres deve falhar", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		longDocs := strings.Repeat("a", 10001)
		client := domain.Client{
			Name:      "Test Client Long Docs",
			Status:    "ativo",
			Documents: &longDocs,
		}

		_, err := clientStore.CreateClient(client)
		if err == nil {
			t.Error("Esperava erro para documents com mais de 10000 caracteres")
		}

		if err != nil && !strings.Contains(err.Error(), "10.000") {
			t.Errorf("Mensagem de erro inesperada: %v", err)
		}
	})

	t.Run("documents com exatamente 10000 caracteres deve ser válido", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		validDocs := strings.Repeat("a", 10000)
		client := domain.Client{
			Name:      "Test Client Valid Docs",
			Status:    "ativo",
			Documents: &validDocs,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Errorf("Não esperava erro para documents com 10000 caracteres: %v", err)
		}

		if id == "" {
			t.Error("ID deveria ser retornado para cliente válido")
		}
	})
}

// TestNullVsEmptyStringPersistence testa persistência de NULL vs string vazia
func TestNullVsEmptyStringPersistence(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	t.Run("email NULL vs vazio", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		empty := ""
		regID1 := "45.723.174/0001-10"
		regID2 := "07.526.557/0001-00"

		client1 := domain.Client{
			Name:           "Client with NULL email",
			Status:         "ativo",
			Email:          nil,
			RegistrationID: &regID1,
		}

		client2 := domain.Client{
			Name:           "Client with empty email",
			Status:         "ativo",
			Email:          &empty,
			RegistrationID: &regID2,
		}

		id1, err := clientStore.CreateClient(client1)
		if err != nil {
			t.Fatalf("Failed to create client1: %v", err)
		}

		id2, err := clientStore.CreateClient(client2)
		if err != nil {
			t.Fatalf("Failed to create client2: %v", err)
		}

		fetched1, err := clientStore.GetClientByID(id1)
		if err != nil {
			t.Fatalf("Failed to fetch client1: %v", err)
		}

		fetched2, err := clientStore.GetClientByID(id2)
		if err != nil {
			t.Fatalf("Failed to fetch client2: %v", err)
		}

		if fetched1.Email != nil {
			t.Error("Email NULL deveria permanecer NULL")
		}

		if fetched2.Email == nil {
			t.Log("String vazia foi convertida para NULL (comportamento válido)")
		} else if *fetched2.Email != "" {
			t.Errorf("String vazia não foi preservada, obteve: '%s'", *fetched2.Email)
		}
	})

	t.Run("campos opcionais com apenas espaços", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		spaces := "   "
		client := domain.Client{
			Name:     "Test Client",
			Status:   "ativo",
			Nickname: &spaces,
			Address:  &spaces,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Nickname != nil && *fetched.Nickname != spaces {
			t.Logf("Nickname com espaços foi alterado: '%s' -> '%s'", spaces, *fetched.Nickname)
		}

		if fetched.Address != nil && *fetched.Address != spaces {
			t.Logf("Address com espaços foi alterado: '%s' -> '%s'", spaces, *fetched.Address)
		}
	})
}

// TestSQLInjectionProtection testa proteção contra SQL injection
func TestSQLInjectionProtection(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	t.Run("SQL injection no nome", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		maliciousName := "'; DROP TABLE clients; --"
		client := domain.Client{
			Name:   maliciousName,
			Status: "ativo",
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Name != maliciousName {
			t.Errorf("Nome não foi preservado corretamente")
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE archived_at IS NULL").Scan(&count)
		if err != nil {
			t.Fatalf("Tabela clients foi comprometida: %v", err)
		}

		if count == 0 {
			t.Error("Tabela clients está vazia - possível SQL injection")
		}
	})

	t.Run("SQL injection em tags", func(t *testing.T) {
		if err := ClearTables(db); err != nil {
			t.Fatalf("Failed to clear tables: %v", err)
		}

		maliciousTags := "vip'; DELETE FROM clients WHERE '1'='1"
		client := domain.Client{
			Name:   "Test Client",
			Status: "ativo",
			Tags:   &maliciousTags,
		}

		id, err := clientStore.CreateClient(client)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		fetched, err := clientStore.GetClientByID(id)
		if err != nil {
			t.Fatalf("Failed to fetch client: %v", err)
		}

		if fetched.Tags == nil || *fetched.Tags != maliciousTags {
			t.Error("Tags não foram preservadas corretamente")
		}
	})
}
