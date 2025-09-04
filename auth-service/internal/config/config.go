package config

import (
    "database/sql"
    "log"
    "os"
    "strconv"

    _ "github.com/go-sql-driver/mysql"
    "github.com/joho/godotenv"
)

type Config struct {
    Port          string
    DB_DSN        string
    JWTSecret     string
    JWTIssuer     string
    JWTTTLMinutes int
}

func Load() *Config {
    _ = godotenv.Load()
    minutes, _ := strconv.Atoi(getEnv("JWT_TTL_MINUTES", "60"))
    return &Config{
        Port:          getEnv("PORT", "8081"),
        DB_DSN:        getEnv("DB_DSN", "root:@tcp(127.0.0.1:3306)/authdb?parseTime=true"),
        JWTSecret:     getEnv("JWT_SECRET", "supersecretchangeme"),
        JWTIssuer:     getEnv("JWT_ISSUER", "my-company"),
        JWTTTLMinutes: minutes,
    }
}

func getEnv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

func MustOpenDB(cfg *Config) *sql.DB {
    db, err := sql.Open("mysql", cfg.DB_DSN)
    if err != nil {
        log.Fatal(err)
    }
    if err := db.Ping(); err != nil {
        log.Fatal(err)
    }
    return db
}
