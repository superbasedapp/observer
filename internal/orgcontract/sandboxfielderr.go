package orgcontract

import (
	"errors"
	"fmt"
)

// The classes of a managed sandbox body field refusal (FieldError.Class).
const (
	// FieldClassInvalid: a value or an entry does not validate.
	FieldClassInvalid = "invalid"
	// FieldClassDuplicate: a list names one entry twice.
	FieldClassDuplicate = "duplicate"
	// FieldClassTooMany: a list is longer than the body allows.
	FieldClassTooMany = "too_many"
)

// FieldError is a managed sandbox body refusal that names the field and the
// class of the problem as structured data, so a caller that records the
// refusal (an audit row, a status line) can say which field without copying
// the refused value (lane FX1, audit finding FX1-A6). Its message is the
// same text the body validators always returned, and it unwraps to
// ErrSandboxManagedBody.
type FieldError struct {
	// Field is the body field's wire path, for example
	// "org_openshell.clone_repositories".
	Field string
	// Class is one of the FieldClass constants.
	Class string
	msg   string
}

// Error is the full refusal text (it may quote the refused value).
func (e *FieldError) Error() string { return e.msg }

// Unwrap answers ErrSandboxManagedBody.
func (e *FieldError) Unwrap() error { return ErrSandboxManagedBody }

// fieldErr builds a FieldError whose message is
// "<ErrSandboxManagedBody>: <detail>".
func fieldErr(field, class, format string, a ...any) error {
	return &FieldError{Field: field, Class: class, msg: ErrSandboxManagedBody.Error() + ": " + fmt.Sprintf(format, a...)}
}

// FieldOf returns the field and class of a body refusal, and false when err
// is not a FieldError.
func FieldOf(err error) (field, class string, ok bool) {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Field, fe.Class, true
	}
	return "", "", false
}
