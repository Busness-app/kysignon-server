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

// MaxInterval is the longest schedule accepted: a year. Beyond that the setting is a way of
// turning backups off without saying so.
const MaxInterval = 366 * 24 * time.Hour

// ErrBadInterval is returned for a schedule outside 0 (off) or [MinBackupDepositInterval, MaxInterval].
var ErrBadInterval = fmt.Errorf("backup: interval must be 0 (off) or between %s and %s", config.MinBackupDepositInterval, MaxInterval)

// SetInterval stores the schedule in whole seconds. Zero disables it; anything else is at
// least config.MinBackupDepositInterval, because each run snapshots the whole database. The
// bound is checked on the seconds before any conversion, so no value wraps to zero.
func SetInterval(settings SettingsStore, sec int64) error {
	if sec != 0 && (sec < int64(config.MinBackupDepositInterval/time.Second) || sec > int64(MaxInterval/time.Second)) {
		return ErrBadInterval
	}
	return settings.SetSetting(settingInterval, strconv.FormatInt(sec, 10))
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
