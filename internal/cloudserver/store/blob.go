package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrBlobMissing is returned by a blob Get when the object is absent (never
// written, already deleted early at a terminal job state, or swept at TTL). The
// worker treats it as evidence_expired semantics — NEVER a retryable provider
// path (substrate §6.2: a Postgres PITR restore may reference an
// already-deleted blob).
var ErrBlobMissing = errors.New("cloudserver/store: evidence blob missing")

// Encryptor is the per-object envelope-encryption seam (substrate §1: Azure
// Blob objects are envelope-encrypted with a Key Vault-wrapped data key). Seal
// wraps plaintext into an opaque ciphertext; Open reverses it. The dev/staging
// driver default is AES-256-GCM with a process (or SBCI_EVIDENCE_KEY-supplied)
// key; the Azure driver swaps a Key Vault path behind the same interface.
type Encryptor interface {
	Seal(plaintext []byte) (ciphertext []byte, err error)
	Open(ciphertext []byte) (plaintext []byte, err error)
}

// BlobStore is the evidence-BYTES seam (plan §6 CI-P4). Put/Get/Delete are all
// account-scoped (RLS-constrained); the reference is the opaque, account-scoped
// key the evidence_objects row carries. The pg bytea PGBlobStore is the
// dev/staging driver; the Azure Blob driver is a later swap.
type BlobStore interface {
	Put(ctx context.Context, accountID, blobRef string, plaintext []byte, now time.Time) error
	Get(ctx context.Context, accountID, blobRef string) ([]byte, error)
	Delete(ctx context.Context, accountID, blobRef string) error
}

// PGBlobStore is the Postgres bytea BlobStore driver. It runs every operation
// inside a tenant transaction (RLS-constrained) and applies the Store's
// Encryptor per object.
type PGBlobStore struct{ s *Store }

// NewPGBlobStore returns the pg bytea blob driver over s.
func NewPGBlobStore(s *Store) *PGBlobStore { return &PGBlobStore{s: s} }

var _ BlobStore = (*PGBlobStore)(nil)

// Put writes the encrypted bytes idempotently (ON CONFLICT DO NOTHING keeps the
// first ciphertext; re-Put of the same reference is a no-op).
func (b *PGBlobStore) Put(ctx context.Context, accountID, blobRef string, plaintext []byte, now time.Time) error {
	return b.s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return putEvidenceBlobTx(ctx, tx, b.s.enc, accountID, blobRef, plaintext, now)
	})
}

// Get loads and decrypts the bytes, or ErrBlobMissing when absent.
func (b *PGBlobStore) Get(ctx context.Context, accountID, blobRef string) ([]byte, error) {
	var ct []byte
	err := b.s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT ciphertext FROM evidence_blobs WHERE account_id = $1::uuid AND blob_ref = $2`,
			accountID, blobRef).Scan(&ct)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrBlobMissing
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	pt, err := b.s.enc.Open(ct)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.Get: decrypt: %w", err)
	}
	return pt, nil
}

// Delete removes the bytes early (terminal job state). Idempotent.
func (b *PGBlobStore) Delete(ctx context.Context, accountID, blobRef string) error {
	return b.s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return deleteEvidenceBlobTx(ctx, tx, accountID, blobRef)
	})
}

// putEvidenceBlobTx encrypts and inserts the bytes inside an existing tenant
// transaction (so job submission can make the blob write atomic with the
// job/evidence-object insert).
func putEvidenceBlobTx(ctx context.Context, tx pgx.Tx, enc Encryptor, accountID, blobRef string, plaintext []byte, now time.Time) error {
	ct, err := enc.Seal(plaintext)
	if err != nil {
		return fmt.Errorf("cloudserver/store.putEvidenceBlob: encrypt: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO evidence_blobs (account_id, blob_ref, ciphertext, size_bytes, created_at)
		 VALUES ($1::uuid, $2, $3, $4, $5)
		 ON CONFLICT (account_id, blob_ref) DO NOTHING`,
		accountID, blobRef, ct, int64(len(plaintext)), now); err != nil {
		return fmt.Errorf("cloudserver/store.putEvidenceBlob: %w", err)
	}
	return nil
}

// deleteEvidenceBlobTx deletes the bytes inside an existing tenant transaction.
func deleteEvidenceBlobTx(ctx context.Context, tx pgx.Tx, accountID, blobRef string) error {
	if blobRef == "" {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM evidence_blobs WHERE account_id = $1::uuid AND blob_ref = $2`,
		accountID, blobRef); err != nil {
		return fmt.Errorf("cloudserver/store.deleteEvidenceBlob: %w", err)
	}
	return nil
}

// --- default AES-256-GCM encryptor ---

type aesGCMEncryptor struct{ aead cipher.AEAD }

// NewAESGCMEncryptor builds an AES-256-GCM Encryptor from a 32-byte key.
func NewAESGCMEncryptor(key []byte) (Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cloudserver/store.NewAESGCMEncryptor: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.NewAESGCMEncryptor: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.NewAESGCMEncryptor: gcm: %w", err)
	}
	return &aesGCMEncryptor{aead: aead}, nil
}

func (e *aesGCMEncryptor) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cloudserver/store: nonce: %w", err)
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *aesGCMEncryptor) Open(ciphertext []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("cloudserver/store: ciphertext too short")
	}
	return e.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// errEncryptor is the fallback when default key generation fails at Store
// construction — every Seal/Open returns the recorded error so evidence bytes
// are never stored in the clear.
type errEncryptor struct{ err error }

func (e errEncryptor) Seal([]byte) ([]byte, error) { return nil, e.err }
func (e errEncryptor) Open([]byte) ([]byte, error) { return nil, e.err }

// newDefaultEncryptor generates a process-random AES-256-GCM encryptor. A
// crash-restart cannot decrypt bytes sealed by a prior process, but free-tier
// evidence lives at most one hour and a restarted worker treats a decrypt
// failure as evidence_expired — acceptable for the dev/staging driver. A
// multi-process deployment (api seals, worker opens) sets SBCI_EVIDENCE_KEY so
// both share a key.
func newDefaultEncryptor() Encryptor {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return errEncryptor{err: fmt.Errorf("cloudserver/store: default key: %w", err)}
	}
	enc, err := NewAESGCMEncryptor(key)
	if err != nil {
		return errEncryptor{err: err}
	}
	return enc
}
