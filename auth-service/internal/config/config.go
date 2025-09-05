package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config menyimpan semua konfigurasi aplikasi
type Config struct {
    DBDSN         string
    JWTSecret     string
    JWTIssuer     string
    JWTExpiration time.Duration
    AppPort       string
}

// LoadConfig memuat konfigurasi dari file .env
func LoadConfig() *Config {
    // Load file .env
    err := godotenv.Load()
    if err != nil {
        log.Println("Warning: .env file not found, using system environment variables")
    }

    // Parse JWT expiration time
    jwtTTLMinutes, err := strconv.Atoi(getEnv("JWT_TTL_MINUTES", "60"))
    if err != nil {
        log.Fatal("Invalid JWT_TTL_MINUTES value")
    }

    return &Config{
        DBDSN:         getEnv("DB_DSN", "root:password@tcp(127.0.0.1:3306)/authdb?parseTime=true"),
        JWTSecret:     getEnv("JWT_SECRET", "fallback_secret_key"),
        JWTIssuer:     getEnv("JWT_ISSUER", "auth-service"),
        JWTExpiration: time.Duration(jwtTTLMinutes) * time.Minute,
        AppPort:       getEnv("APP_PORT", "8080"),
    }
}

// getEnv helper function untuk membaca environment variable
func getEnv(key, defaultValue string) string {
    value := os.Getenv(key)
    if value == "" {
        return defaultValue
    }
    return value
}