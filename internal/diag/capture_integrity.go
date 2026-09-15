package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// CaptureIntegritySignals is the content-free result of checking whether the
// node's registered capture hooks still match its recorded local posture.
// Risks are positive observations; Unknown contains checks that could not
// produce a result. Neither slice contains paths, commands, errors, or values.
type CaptureIntegritySignals struct {
	Risks   []string
	Unknown []string
}

type captureRegistryEntry struct {
	SHA256     string `json:"sha256"`
	BinaryPath string `json:"binary_path"`
	LastResult string `json:"last_result"`
}

const (
	maxCaptureRegistryBytes = 1 << 20
	maxCaptureConfigBytes   = 4 << 20
)

// InspectCaptureIntegrity reads the hook registry and Codex trust posture and
// returns only closed labels from orgcontract. A whole-config checksum change
// is reported as review-required evidence because tool config files also hold
// unrelated settings; it is never classified as proof of capture bypass.
func InspectCaptureIntegrity(homeDir, binaryPath string) CaptureIntegritySignals {
	risks := map[string]bool{}
	unknown := map[string]bool{}
	registryPath := filepath.Join(homeDir, ".observer", "hook_checksums.json")
	raw, err := readBoundedRegularFile(registryPath, maxCaptureRegistryBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			unknown[orgcontract.CaptureUnknownRegistryMissing] = true
		} else {
			unknown[orgcontract.CaptureUnknownRegistryUnreadable] = true
		}
	} else {
		var entries map[string]captureRegistryEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			unknown[orgcontract.CaptureUnknownRegistryInvalid] = true
		} else if len(entries) == 0 {
			unknown[orgcontract.CaptureUnknownRegistryEmpty] = true
		} else {
			inspectCaptureRegistryEntries(entries, binaryPath, risks, unknown)
		}
	}

	trust := checkCodexHookTrust(homeDir)
	if trust.Status == StatusWarn {
		if len(trust.Details) > 0 && strings.HasPrefix(trust.Details[0], "untrusted:") {
			risks[orgcontract.CaptureRiskCodexHookUntrusted] = true
		} else {
			unknown[orgcontract.CaptureUnknownCodexTrust] = true
		}
	}

	return CaptureIntegritySignals{
		Risks:   sortedCaptureLabels(risks),
		Unknown: sortedCaptureLabels(unknown),
	}
}

func inspectCaptureRegistryEntries(entries map[string]captureRegistryEntry, binaryPath string, risks, unknown map[string]bool) {
	if strings.TrimSpace(binaryPath) == "" {
		unknown[orgcontract.CaptureUnknownBinaryPath] = true
	}
	for configPath, entry := range entries {
		if entry.LastResult == "error" {
			risks[orgcontract.CaptureRiskHookRegistrationError] = true
		}
		body, err := readBoundedRegularFile(configPath, maxCaptureConfigBytes)
		switch {
		case err != nil:
			if errors.Is(err, os.ErrNotExist) {
				risks[orgcontract.CaptureRiskHookConfigMissing] = true
			} else {
				unknown[orgcontract.CaptureUnknownConfigUnreadable] = true
			}
		case strings.TrimSpace(entry.SHA256) == "":
			unknown[orgcontract.CaptureUnknownChecksumMissing] = true
		default:
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != entry.SHA256 {
				risks[orgcontract.CaptureRiskHookConfigChanged] = true
			}
		}

		switch {
		case strings.TrimSpace(entry.BinaryPath) == "":
			unknown[orgcontract.CaptureUnknownRecordedBinary] = true
		case strings.TrimSpace(binaryPath) != "" && filepath.Clean(entry.BinaryPath) != filepath.Clean(binaryPath):
			risks[orgcontract.CaptureRiskHookBinaryMismatch] = true
		}
	}
}

func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte check limit", maxBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte check limit", maxBytes)
	}
	return body, nil
}

func sortedCaptureLabels(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for label := range set {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}
