package main

import (
	"fmt"
	"log"
	"net/http"

	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/store"

	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	// Configuração de log em arquivo com rotação
	log.SetOutput(&lumberjack.Logger{
		Filename:   "backend.log",
		MaxSize:    5,    // megabytes
		MaxBackups: 3,    // quantos arquivos antigos manter
		MaxAge:     30,   // dias
		Compress:   true, // comprimir arquivos antigos
	})

	db, err := database.ConnectDB()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	server := &Server{
		userStore:      store.NewUserStore(db),
		contractStore:  store.NewContractStore(db),
		clientStore:    store.NewClientStore(db),
		dependentStore: store.NewDependentStore(db),
		categoryStore:  store.NewCategoryStore(db),
		lineStore:      store.NewLineStore(db),
	}

	server.setupRoutes()

	fmt.Println("Server running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
