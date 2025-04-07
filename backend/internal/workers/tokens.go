package workers

import (
	"context"
	"time"

	"github.com/irrisdev/goforum/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// TokenCleanupWorker manages the refresh token cleanup job
type TokenCleanupWorker struct {
	db             *gorm.DB
	interval       time.Duration
	shutdownCh     chan struct{}
	retainDuration time.Duration
}

// NewTokenCleanupWorker creates a new token cleanup worker
func NewTokenCleanupWorker(db *gorm.DB) *TokenCleanupWorker {
	return &TokenCleanupWorker{
		db:             db,
		interval:       24 * time.Hour,
		shutdownCh:     make(chan struct{}),
		retainDuration: 7 * 24 * time.Hour,
	}
}

// SetInterval changes how often the cleanup job runs
func (w *TokenCleanupWorker) SetInterval(d time.Duration) {
	w.interval = d
}

// SetRetainDuration changes how long to keep expired/revoked tokens
func (w *TokenCleanupWorker) SetRetainDuration(d time.Duration) {
	w.retainDuration = d
}

// Start begins the token cleanup worker
func (w *TokenCleanupWorker) Start(ctx context.Context) {
	logrus.Info("starting token cleanup worker")

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.cleanup()
		case <-ctx.Done():
			logrus.Info("shutting down token cleanup worker due to context cancellation")
			return
		case <-w.shutdownCh:
			logrus.Info("shutting down token cleanup worker")
			return
		}

	}
}

// Stop halts the cleanup worker
func (w *TokenCleanupWorker) Stop() {
	close(w.shutdownCh)
}

func (w *TokenCleanupWorker) cleanup() {
	logger := logrus.WithField("worker", "token_cleanup")
	logger.Info("starting refresh token cleanup")

	deleteBefore := time.Now().UTC().Add(-w.retainDuration)

	// Delete revoked tokens that are older than threshold
	revokedResult := w.db.Where("is_revoked = ? AND issued_at < ?", true, deleteBefore).Delete(&models.RefreshToken{})
	if revokedResult.Error != nil {
		logger.WithError(revokedResult.Error).Error("failed to clean up revoked tokens")
	} else {
		logger.WithField("revoked_deleted", revokedResult.RowsAffected).Info("cleaned up revoked tokens")
	}

	// Delete expired tokens that are older than threshold
	expiredResult := w.db.Where("expires_at < ? AND is_revoked < ?", deleteBefore, false).Delete(&models.RefreshToken{})

	if expiredResult.Error != nil {
		logger.WithError(expiredResult.Error).Error("failed to clean up expired tokens")
	} else {
		logger.WithField("expired_deleted", expiredResult.RowsAffected).Info("cleaned up expired tokens")
	}

	totalDeleted := expiredResult.RowsAffected + revokedResult.RowsAffected
	logger.WithField("total_deleted", totalDeleted).Info("token cleanup completed")
}
