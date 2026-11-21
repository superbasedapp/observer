package platformcontract

import (
	"errors"
	"fmt"
	"time"
)

// ValidationError is the typed error every Validate returns.
type ValidationError struct {
	// Field is the JSON field name at fault.
	Field string
	// Reason is a short fixed phrase.
	Reason string
}

// Error implements error.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("platformcontract: invalid %s: %s", e.Field, e.Reason)
}

// IsValidation reports whether err is (or wraps) a *ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

func need(field, v string) error {
	if blank(v) {
		return &ValidationError{Field: field, Reason: "required"}
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func enum(field string, ok bool) error {
	if !ok {
		return &ValidationError{Field: field, Reason: "unknown value"}
	}
	return nil
}

func nonNeg(field string, n int64) error {
	if n < 0 {
		return &ValidationError{Field: field, Reason: "must not be negative"}
	}
	return nil
}

// ValidDay reports whether s is a YYYY-MM-DD calendar date.
func ValidDay(s string) bool {
	t, err := time.Parse("2006-01-02", s)
	return err == nil && t.Format("2006-01-02") == s
}

// Validate checks the document's shape (not its signature).
func (d EntitlementDocument) Validate() error {
	if d.Version <= 0 {
		return &ValidationError{Field: "version", Reason: "must be positive"}
	}
	if len(d.Body) == 0 {
		return &ValidationError{Field: "body", Reason: "required"}
	}
	if len(d.Signature) == 0 {
		return &ValidationError{Field: "signature", Reason: "required"}
	}
	return need("key_id", d.KeyID)
}

// Validate checks the request.
func (r CreateTenantRequest) Validate() error {
	if err := firstErr(need("idempotency_key", r.IdempotencyKey), need("tenant_id", r.TenantID),
		need("name", r.Name), need("owner_sub", r.OwnerSub), need("owner_email", r.OwnerEmail)); err != nil {
		return fmt.Errorf("platformcontract.CreateTenantRequest.Validate: %w", err)
	}
	if err := r.Entitlements.Validate(); err != nil {
		return fmt.Errorf("platformcontract.CreateTenantRequest.Validate: entitlements: %w", err)
	}
	return nil
}

// Validate checks the request.
func (r SetStateRequest) Validate() error {
	if err := firstErr(need("tenant_id", r.TenantID), enum("state", r.State.Valid()),
		nonNeg("lifecycle_gen", r.LifecycleGen)); err != nil {
		return fmt.Errorf("platformcontract.SetStateRequest.Validate: %w", err)
	}
	return nil
}

// Validate checks the request.
func (r SetEntitlementsRequest) Validate() error {
	if err := need("tenant_id", r.TenantID); err != nil {
		return fmt.Errorf("platformcontract.SetEntitlementsRequest.Validate: %w", err)
	}
	if err := r.Document.Validate(); err != nil {
		return fmt.Errorf("platformcontract.SetEntitlementsRequest.Validate: document: %w", err)
	}
	return nil
}

// Validate checks the envelope's shape (its signature is the host's check,
// VerifyAvailability).
func (d AvailabilityDocument) Validate() error {
	return EntitlementDocument(d).Validate()
}

// Validate checks the request.
func (r SetAvailabilityRequest) Validate() error {
	if err := r.Document.Validate(); err != nil {
		return fmt.Errorf("platformcontract.SetAvailabilityRequest.Validate: document: %w", err)
	}
	return nil
}

// Validate checks the request.
func (r DeactivateMemberRequest) Validate() error {
	if err := firstErr(need("tenant_id", r.TenantID), need("sub", r.Sub),
		need("idempotency_key", r.IdempotencyKey)); err != nil {
		return fmt.Errorf("platformcontract.DeactivateMemberRequest.Validate: %w", err)
	}
	return nil
}

// Validate checks the request.
func (r EvictRequest) Validate() error {
	if err := firstErr(need("tenant_id", r.TenantID), nonNeg("lifecycle_gen", r.LifecycleGen)); err != nil {
		return fmt.Errorf("platformcontract.EvictRequest.Validate: %w", err)
	}
	return nil
}

// Validate checks the request.
func (r UsageRequest) Validate() error {
	if !ValidDay(r.Day) {
		return fmt.Errorf("platformcontract.UsageRequest.Validate: %w",
			&ValidationError{Field: "day", Reason: "must be YYYY-MM-DD"})
	}
	return nil
}

// Validate checks the request.
func (r RouteCheckRequest) Validate() error {
	if err := need("tenant_id", r.TenantID); err != nil {
		return fmt.Errorf("platformcontract.RouteCheckRequest.Validate: %w", err)
	}
	return nil
}

// Validate checks the response enums.
func (r HealthResponse) Validate() error {
	if err := firstErr(need("tenant_id", r.TenantID), enum("status", r.Status.Valid()),
		enum("last_push", r.LastPush.Valid()), enum("backlog", r.Backlog.Valid()),
		enum("quota", r.Quota.Valid()), enum("error", r.Error.Valid())); err != nil {
		return fmt.Errorf("platformcontract.HealthResponse.Validate: %w", err)
	}
	return nil
}
