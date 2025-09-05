package main

import (
	"auth-service/internal/config"
	"auth-service/internal/router"
	"database/sql"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
    // Load konfigurasi
    cfg := config.LoadConfig()

    // Koneksi ke database MySQL
    db, err := sql.Open("mysql", cfg.DBDSN)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()

    // Test koneksi database
    err = db.Ping()
    if err != nil {
        log.Fatal("Failed to ping database:", err)
    }
    log.Println("Connected to database successfully")

    // Set pool connections
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(25)
    db.SetConnMaxLifetime(5 * time.Minute)

    // Setup router
    r := router.SetupRouter(db, cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTExpiration)

    // Jalankan server
    log.Printf("Server starting on port %s", cfg.AppPort)
    log.Fatal(r.Run(":" + cfg.AppPort))
}