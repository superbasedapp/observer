package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
)

// InterventionAuthority is a consistent local authority snapshot. It carries
// no bearer credentials and authorizes nothing by itself; the governance owner
// must validate its scope, generation, key and grant before acting.
type InterventionAuthority struct {
	Enrolment      *Enrolment
	Generation     EnrolmentGeneration
	HaveGeneration bool
	Grant          EnrolmentGrant
	HaveGrant      bool
	KeyPinSHA256   string
	BudgetWitness  OrgBudgetWitness
	PricingWitness OrgPricingWitness
}

// ErrOrgBudgetWitnessChanged means the durable budget document no longer
// matches the exact present/absent snapshot that produced an intervention.
var ErrOrgBudgetWitnessChanged = errors.New("org budget document changed")

// ErrOrgPricingWitnessChanged means the durable pricing document no longer
// matches the exact state consumed by a measured USD decision.
var ErrOrgPricingWitnessChanged = errors.New("org pricing document changed")

// WithInterventionFence serializes one bounded process-control operation with
// enrollment, generation, grant, key-pin, budget and optional pricing writes,
// including other processes. Pricing is required only for a measured USD
// decision; nil means the policy result consumed no price-table document.
// It uses the same BEGIN IMMEDIATE boundary as policy-resource installation.
// The callback must only evaluate this snapshot and operate its existing OS
// handle; it must not read/write the store, make network calls or start work.
// The pinned connection supplies every read, including with a one-connection
// pool. No database state is changed and the transaction is rolled back.
func (s *Store) WithInterventionFence(ctx context.Context, orgKey, pinPath string, expectedBudget OrgBudgetWitness, expectedPricing *OrgPricingWitness, fn func(InterventionAuthority) error) (err error) {
	if s == nil || ctx == nil || fn == nil || orgKey == "" || pinPath == "" || !expectedBudget.Valid() ||
		(expectedPricing != nil && !expectedPricing.Valid()) {
		return errors.New("store.WithInterventionFence: missing inputs")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("store.WithInterventionFence: deadline required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store.WithInterventionFence: connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store.WithInterventionFence: begin: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, releaseErr := conn.ExecContext(cleanup, "ROLLBACK")
		if releaseErr != nil {
			// A failed rollback must not return a still-locked connection to
			// the pool and obstruct enrollment or ordinary capture indefinitely.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("store.WithInterventionFence: release: %w", releaseErr))
		}
	}()
	var snapshot InterventionAuthority
	if snapshot.Enrolment, err = loadEnrolment(ctx, conn); err != nil {
		return err
	}
	if snapshot.Generation, snapshot.HaveGeneration, err = loadEnrolmentGeneration(ctx, conn, orgKey); err != nil {
		return err
	}
	if snapshot.Grant, snapshot.HaveGrant, err = loadEnrolmentGrant(ctx, conn, orgKey); err != nil {
		return err
	}
	if snapshot.KeyPinSHA256, _, err = readOrgPolicyKeyPin(ctx, conn, pinPath); err != nil {
		return err
	}
	if snapshot.BudgetWitness, err = loadOrgBudgetWitness(ctx, conn); err != nil {
		return err
	}
	if snapshot.BudgetWitness != expectedBudget {
		return ErrOrgBudgetWitnessChanged
	}
	if expectedPricing != nil {
		if snapshot.PricingWitness, err = loadOrgPricingWitness(ctx, conn); err != nil {
			return err
		}
		if snapshot.PricingWitness != *expectedPricing {
			return ErrOrgPricingWitnessChanged
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(snapshot)
}
