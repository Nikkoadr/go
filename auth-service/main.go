package main

import (
    "auth-service/internal/config"
    "auth-service/internal/router"
    "log"
)

func main() {
    cfg := config.Load()
    db := config.MustOpenDB(cfg)
    r := router.SetupRouter(cfg, db)

    log.Printf("Auth service running on :%s", cfg.Port)
    if err := r.Run(":" + cfg.Port); err != nil {
        log.Fatal(err)
    }
}
