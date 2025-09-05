package repository

import (
	"auth-service/internal/model"
	"database/sql"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// UserRepository interface untuk operasi database pengguna
type UserRepository interface {
    Migrate() error
    CreateUser(user *model.User) error
    FindByEmail(email string) (*model.User, error)
    FindByID(id int64) (*model.User, error)
}

type userRepository struct {
    db *sql.DB
}

// NewUserRepository membuat instance baru UserRepository
func NewUserRepository(db *sql.DB) UserRepository {
    return &userRepository{db: db}
}

// Migrate membuat tabel users jika belum ada
func (r *userRepository) Migrate() error {
    query := `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `

    _, err := r.db.Exec(query)
    if err != nil {
        return fmt.Errorf("failed to create users table: %v", err)
    }

    log.Println("Users table migrated successfully")
    return nil
}

// CreateUser menyimpan pengguna baru ke database
func (r *userRepository) CreateUser(user *model.User) error {
    query := `INSERT INTO users (name, email, password_hash, role, created_at) 
              VALUES (?, ?, ?, ?, ?)`

    result, err := r.db.Exec(query, user.Name, user.Email, user.PasswordHash, user.Role, user.CreatedAt)
    if err != nil {
        return fmt.Errorf("failed to create user: %v", err)
    }

    userID, err := result.LastInsertId()
    if err != nil {
        return fmt.Errorf("failed to get last insert ID: %v", err)
    }

    user.ID = userID
    return nil
}

// FindByEmail mencari pengguna berdasarkan email
func (r *userRepository) FindByEmail(email string) (*model.User, error) {
    query := `SELECT id, name, email, password_hash, role, created_at 
              FROM users WHERE email = ?`

    row := r.db.QueryRow(query, email)
    user := &model.User{}

    err := row.Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found")
        }
        return nil, fmt.Errorf("failed to query user: %v", err)
    }

    return user, nil
}

// FindByID mencari pengguna berdasarkan ID
func (r *userRepository) FindByID(id int64) (*model.User, error) {
    query := `SELECT id, name, email, password_hash, role, created_at 
              FROM users WHERE id = ?`

    row := r.db.QueryRow(query, id)
    user := &model.User{}

    err := row.Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found")
        }
        return nil, fmt.Errorf("failed to query user: %v", err)
    }

    return user, nil
}

// HashPassword menghasilkan hash dari password menggunakan bcrypt
func HashPassword(password string) (string, error) {
    hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", fmt.Errorf("failed to hash password: %v", err)
    }
    return string(hashedBytes), nil
}

// CheckPassword memverifikasi password dengan hash
func CheckPassword(password, hash string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}