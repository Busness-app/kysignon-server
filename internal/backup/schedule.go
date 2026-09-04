package backup

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/store"
)

const (
	settingInterval    = "backup_interval_sec"
	settingLastAttempt = "backup_last_attempt"
)

// Interval is the backup schedule: the admin's setting when one exists, else the
// KYSIGNON_BACKUP_DEPOSIT_INTERVAL default. Zero means off.
func Interval(cfg *config.Config, settings SettingsStore) (time.Duration, error) {
	v, err := settings.GetSetting(settingInterval)
	if errors.Is(err, store.ErrNotFound) {
		return cfg.BackupDepositInterval, nil
	}
	if err != nil {
		return 0, err
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", settingInterval, err)
	}
	return time.Duration(sec) * time.Second, nil
}

// SetInterval stores the schedule. Zero disables it; anything else is at least
// config.MinBackupDepositInterval, because each run snapshots the whole database.
func SetInterval(settings SettingsStore, d time.Duration) error {
	if d < 0 || (d != 0 && d < config.MinBackupDepositInterval) {
		return fmt.Errorf("backup: interval must be 0 (off) or at least %s", config.MinBackupDepositInterval)
	}
	return settings.SetSetting(settingInterval, strconv.FormatInt(int64(d/time.Second), 10))
}

// NextRun is when the scheduler will next back up, or ok=false when the schedule is off.
// It counts from the last attempt, successful or not, so a failing destination is retried
// once per interval rather than every tick.
func NextRun(cfg *config.Config, settings SettingsStore) (time.Time, bool, error) {
	interval, err := Interval(cfg, settings)
	if err != nil || interval == 0 {
		return time.Time{}, false, err
	}
	last, err := lastAttempt(settings)
	if err != nil {
		return time.Time{}, false, err
	}
	if last.IsZero() {
		return time.Now().UTC(), true, nil
	}
	return last.Add(interval), true, nil
}

func lastAttempt(settings SettingsStore) (time.Time, error) {
	v, err := settings.GetSetting(settingLastAttempt)
	if errors.Is(err, store.ErrNotFound) || (err == nil && v == "") {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, v)
}

func markAttempt(settings SettingsStore) error {
	return settings.SetSetting(settingLastAttempt, time.Now().UTC().Format(time.RFC3339))
}
