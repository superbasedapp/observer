package cloudcred

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const recLegacyHost = "legacy-adoption-host"

// adoptLegacyBundle claims one destination for BOTH legacy records before
// copying either. The durable claim survives crashes between copy and cleanup;
// the process lock prevents two hosts adopting the same bearer or refresh.
func adoptLegacyBundle(dir, host string, get func(string) (string, error), set func(string, string) error, remove func(string) error) error {
	// On platforms without a verified private coordination directory, require
	// a fresh sign-in. Scoped keychain credentials continue working normally.
	if !fileFallbackSecure() {
		return ErrNotFound
	}
	return withCredentialLock(dir, func() error {
		coord := &fileStore{dir: dir}
		claim, err := coord.read(recLegacyHost)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && string(claim) != host {
			return ErrNotFound
		}
		legacy := make(map[string]string)
		for _, rec := range []string{recAPIToken, recWorkOSRefresh} {
			v, err := get(rec)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil {
				legacy[rec] = v
			}
		}
		if len(legacy) == 0 {
			return nil
		}
		if len(claim) == 0 {
			if err := coord.write(recLegacyHost, []byte(host)); err != nil {
				return err
			}
		}
		for _, rec := range []string{recAPIToken, recWorkOSRefresh} {
			value, present := legacy[rec]
			if !present {
				continue
			}
			scoped := recordName(rec, host)
			if _, err := get(scoped); errors.Is(err, ErrNotFound) {
				if err := set(scoped, value); err != nil {
					return fmt.Errorf("cloudcred: adopt legacy bundle: %w", err)
				}
			} else if err != nil {
				return err
			}
			if err := remove(rec); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("cloudcred: remove adopted legacy record: %w", err)
			}
		}
		return nil
	})
}

// The keychain service is shared across node directories, so its migration
// lock and claim must also be per OS user rather than per fallbackDir.
func keychainCoordDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cloudcred: resolve keychain coordination directory: %w", err)
	}
	return filepath.Join(dir, ServiceName), nil
}
