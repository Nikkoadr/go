package repository

import (
    "auth-service/internal/model"
    "context"
    "database/sql"
    "errors"
)

type AuthRepository struct {
    DB *sql.DB
}

func New(db *sql.DB) *AuthRepository {
    r := &AuthRepository{DB: db}
    r.autoMigrate()
    return r
}

func (r *AuthRepository) autoMigrate() {
    query := `
    CREATE TABLE IF NOT EXISTS user (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(120) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );`
    r.DB.Exec(query)
}

func (r *AuthRepository) CreateUser(ctx context.Context, u *model.User) error {
    q := `INSERT INTO user (name, email, password_hash) VALUES (?, ?, ?)`
    res, err := r.DB.ExecContext(ctx, q, u.Name, u.Email, u.PasswordHash)
    if err != nil {
        return err
    }
    u.ID, _ = res.LastInsertId()
    return nil
}

func (r *AuthRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
    q := `SELECT id, name, email, password_hash, created_at, updated_at FROM user WHERE email = ?`
    row := r.DB.QueryRowContext(ctx, q, email)
    var u model.User
    if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, nil
        }
        return nil, err
    }
    return &u, nil
}
