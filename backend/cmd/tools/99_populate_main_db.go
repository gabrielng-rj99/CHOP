package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
)

func populateMainDB() {
	fmt.Println("=== Populando banco de dados principal ===")

	// Configuração do banco
	dbHost := "localhost"
	dbPort := "5432"
	dbName := os.Getenv("POSTGRES_DB")
	if dbName == "" {
		dbName = "contracts_manager"
	}
	dbUser := "postgres"
	dbPass := "postgres"

	// Exporta variável de ambiente para psql
	os.Setenv("PGPASSWORD", dbPass)

	// Hash fixo para senha 'pass123' gerado com bcrypt (custo 12)
	pass123Hash := "$2b$12$wI6pQwQwQwQwQwQwQwQwQeQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw"

	adminID := uuid.New().String()
	adminUsername := "admin"
	adminDisplayName := "Administrador"
	adminRole := "root"

	fmt.Println("Populando usuários...")
	runPSQL(fmt.Sprintf(`
		INSERT INTO users (id, username, display_name, password_hash, created_at, role)
		VALUES ('%s', '%s', '%s', '%s', NOW(), '%s');
	`, adminID, adminUsername, adminDisplayName, pass123Hash, adminRole), dbHost, dbPort, dbUser, dbName)

	for i := 1; i <= 20; i++ {
		userID := uuid.New().String()
		username := fmt.Sprintf("user%d", i)
		displayName := fmt.Sprintf("Usuário %d", i)
		role := "user"
		runPSQL(fmt.Sprintf(`
			INSERT INTO users (id, username, display_name, password_hash, created_at, role)
			VALUES ('%s', '%s', '%s', '%s', NOW(), '%s');
		`, userID, username, displayName, pass123Hash, role), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("Populando clientes...")
	for i := 1; i <= 20; i++ {
		clientID := uuid.New().String()
		name := fmt.Sprintf("Cliente %d", i)
		regID := fmt.Sprintf("REG%d", i)
		nickname := fmt.Sprintf("Cli%d", i)
		email := fmt.Sprintf("cliente%d@example.com", i)
		phone := fmt.Sprintf("555-100%d", i)
		address := fmt.Sprintf("Rua Exemplo, %d", i)
		birthDate := fmt.Sprintf("1980-01-0%d", (i%9)+1)
		notes := fmt.Sprintf("Observações sobre o Cliente %d", i)
		runPSQL(fmt.Sprintf(`
			INSERT INTO clients (id, name, registration_id, nickname, birth_date, email, phone, address, notes, status, tags, contact_preference, created_at)
			VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 'ativo', 'tag1,tag2', 'whatsapp', NOW());
		`, clientID, name, regID, nickname, birthDate, email, phone, address, notes), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("Populando dependentes...")
	for i := 1; i <= 20; i++ {
		depID := uuid.New().String()
		depName := fmt.Sprintf("Dependente %d", i)
		description := fmt.Sprintf("Descrição do Dependente %d", i)
		email := fmt.Sprintf("dep%d@example.com", i)
		phone := fmt.Sprintf("555-200%d", i)
		address := fmt.Sprintf("Rua Dependente, %d", i)
		birthDate := fmt.Sprintf("2000-02-0%d", (i%9)+1)
		notes := fmt.Sprintf("Notas sobre o Dependente %d", i)
		runPSQL(fmt.Sprintf(`
			INSERT INTO dependents (id, name, client_id, description, birth_date, email, phone, address, notes, status, tags, contact_preference)
			VALUES ('%s', '%s', (SELECT id FROM clients ORDER BY created_at LIMIT 1 OFFSET %d), '%s', '%s', '%s', '%s', '%s', '%s', 'ativo', 'dep_tag', 'email');
		`, depID, depName, i-1, description, birthDate, email, phone, address, notes), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("Populando categorias...")
	for i := 1; i <= 20; i++ {
		catID := uuid.New().String()
		catName := fmt.Sprintf("Categoria %d", i)
		runPSQL(fmt.Sprintf(`
			INSERT INTO categories (id, name)
			VALUES ('%s', '%s');
		`, catID, catName), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("Populando linhas...")
	for i := 1; i <= 20; i++ {
		lineID := uuid.New().String()
		lineName := fmt.Sprintf("Linha %d", i)
		runPSQL(fmt.Sprintf(`
			INSERT INTO lines (id, name, category_id)
			VALUES ('%s', '%s', (SELECT id FROM categories ORDER BY name LIMIT 1 OFFSET %d));
		`, lineID, lineName, i-1), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("Populando contratos...")
	for i := 1; i <= 20; i++ {
		contractID := uuid.New().String()
		model := fmt.Sprintf("Modelo %d", i)
		productKey := fmt.Sprintf("PRODKEY%d", i)
		startDate := fmt.Sprintf("2024-01-0%d 00:00:00", (i%9)+1)

		// Metade dos contratos com data de fim, metade sem (permanentes)
		var endDateSQL string
		if i%2 == 0 {
			endDate := fmt.Sprintf("2025-01-0%d 00:00:00", (i%9)+1)
			endDateSQL = fmt.Sprintf("'%s'", endDate)
		} else {
			endDateSQL = "NULL"
		}

		// Metade dos contratos com dependente, metade sem
		var dependentSQL string
		if i%2 == 0 {
			dependentSQL = fmt.Sprintf("(SELECT id FROM dependents ORDER BY name LIMIT 1 OFFSET %d)", i-1)
		} else {
			dependentSQL = "NULL"
		}

		runPSQL(fmt.Sprintf(`
			INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id)
			VALUES ('%s', '%s', '%s', '%s', %s,
				(SELECT id FROM lines ORDER BY name LIMIT 1 OFFSET %d),
				(SELECT id FROM clients ORDER BY created_at LIMIT 1 OFFSET %d),
				%s);
		`, contractID, model, productKey, startDate, endDateSQL, i-1, i-1, dependentSQL), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("Populando audit_logs...")
	for i := 1; i <= 20; i++ {
		logID := uuid.New().String()
		operation := "insert"
		entity := "contract"
		status := "success"
		fixedDate := "2024-10-10"
		runPSQL(fmt.Sprintf(`
			INSERT INTO audit_logs (id, operation, entity, entity_id, admin_id, admin_username, status, created_at)
			VALUES ('%s', '%s', '%s', (SELECT id FROM contracts ORDER BY start_date LIMIT 1 OFFSET %d), '%s', '%s', '%s', '%s');
		`, logID, operation, entity, i-1, adminID, adminUsername, status, fixedDate), dbHost, dbPort, dbUser, dbName)
	}

	fmt.Println("População concluída!")
}

// runPSQL executa um comando SQL usando psql
func runPSQL(sql string, host, port, user, dbname string) {
	cmd := exec.Command(
		"psql",
		"-h", host,
		"-p", port,
		"-U", user,
		"-d", dbname,
		"-c", sql,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Para evitar travar se psql pedir senha, já exportamos PGPASSWORD antes
	if err := cmd.Run(); err != nil {
		fmt.Printf("Erro ao executar SQL: %s\n%s\n", sql, err)
		time.Sleep(500 * time.Millisecond)
	}
}
