package main

import (
	"efss-server/db"
	"efss-server/handlers"
	"efss-server/middleware"
	"log"
	"net/http"
	"os"
)

func main() {
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		connString = "postgres://postgres:postgres@localhost:5432/cryptoexchange?sslmode=disable"
	}

	if err := db.Init(connString); err != nil {
		log.Fatal("errore inizializzazione DB:", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", handlers.Register)
	mux.HandleFunc("POST /login", handlers.Login)
	mux.HandleFunc("POST /logout", middleware.RequireAuth(handlers.Logout))

	mux.HandleFunc("GET /keys/{username}", middleware.RequireAuth(handlers.GetPublicKey))

	mux.HandleFunc("POST /mailbox/send", middleware.RequireAuth(handlers.SendMessage))
	mux.HandleFunc("GET /mailbox/inbox", middleware.RequireAuth(handlers.Inbox))
	mux.HandleFunc("GET /mailbox/download/{id}", middleware.RequireAuth(handlers.Download))

	log.Println("Server in ascolto su :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
