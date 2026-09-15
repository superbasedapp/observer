//go:build linux

package main

import (
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/intervention/inspectionbroker"
)

func nodeInterventionScanOptions(uid, controllerPID int) intervention.ScanOptions {
	client := inspectionbroker.Client{SocketPath: inspectionbroker.DefaultSocketPath(uid), TargetUID: uid}
	return intervention.ScanOptions{TargetUID: uid, ControllerPID: controllerPID, InspectProtected: client.Inspect}
}
