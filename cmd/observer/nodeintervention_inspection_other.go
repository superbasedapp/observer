//go:build !linux

package main

import "github.com/marmutapp/superbased-observer/internal/intervention"

func nodeInterventionScanOptions(uid, controllerPID int) intervention.ScanOptions {
	return intervention.ScanOptions{TargetUID: uid, ControllerPID: controllerPID}
}
