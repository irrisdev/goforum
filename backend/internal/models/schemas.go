package models

import "time"

// Represents a user in the forum
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique;not null"`
	Email     string `gorm:"unique;not null"`
	Password  string `gorm:"not null"`
	CreatedAt time.Time
}

// Represents a category in the forum
type Category struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;size:50;not null;uniqueIndex"`
	Description string `gorm:"size:200"`
	CreatedAt   time.Time
}

// Represents a thread in the forum
type Thread struct {
	ID         uint   `gorm:"primaryKey"`
	Title      string `gorm:"not null"`
	Content    string `gorm:"not null"`
	UserID     uint   `gorm:"not null"`
	CategoryID uint   `gorm:"not null"`
	CreatedAt  time.Time
}

// Represents a reply to a thread
type Reply struct {
	ID        uint   `gorm:"primaryKey"`
	Content   string `gorm:"not null"`
	UserID    uint   `gorm:"not null"`
	ThreadID  uint   `gorm:"not null"`
	CreatedAt time.Time
}

// Represents a refresh token
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	Token     string    `gorm:"not null;index:idx_token_user,unique:idx_token_user"`
	UserID    uint      `gorm:"not null;index:idx_token_user,unique:idx_token_user"`
	User      User      `gorm:"foreignKey:UserID"`
	ExpiresAt time.Time `gorm:"not null"`
	IssuedAt  time.Time `gorm:"not null"`
	IsRevoked bool      `gorm:"default:false"`
}
