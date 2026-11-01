package sandboxhcs

import (
	"encoding/json"
	"fmt"
	"strings"
)

// document.go plans the two HCS schema v2 compute system documents of one
// run: the utility VM (Hyper-V isolation, with NO network adapter: the
// row's only tier is none) and the container it hosts, whose storage is the
// image's layers and whose mapped directories are the workspace (read-write
// or read-only by the source rules) and the protected paths (read-only).
// The field names follow the HCS schema v2 reference (SchemaVersion,
// Owner, ShouldTerminateOnLastHandleClosed, VirtualMachine.ComputeTopology,
// Container.Storage.Layers, Container.MappedDirectories with HostPath,
// ContainerPath and ReadOnly, HostingSystemId); no live run has used them
// (register WIN-10).

// SchemaVersion is the document's schema version.
type SchemaVersion struct {
	Major int `json:"Major"`
	Minor int `json:"Minor"`
}

// Layer is one image layer.
type Layer struct {
	ID   string `json:"Id"`
	Path string `json:"Path"`
}

// MappedDirectory maps a host folder into the container.
type MappedDirectory struct {
	HostPath      string `json:"HostPath"`
	ContainerPath string `json:"ContainerPath"`
	ReadOnly      bool   `json:"ReadOnly"`
}

// UtilityVM is the hosting compute system.
type UtilityVM struct {
	Owner                             string         `json:"Owner"`
	SchemaVersion                     SchemaVersion  `json:"SchemaVersion"`
	ShouldTerminateOnLastHandleClosed bool           `json:"ShouldTerminateOnLastHandleClosed"`
	VirtualMachine                    VirtualMachine `json:"VirtualMachine"`
}

// VirtualMachine is the utility VM's hardware: memory and processors, and
// no Devices.NetworkAdapters (no network).
type VirtualMachine struct {
	StopOnReset     bool            `json:"StopOnReset"`
	ComputeTopology ComputeTopology `json:"ComputeTopology"`
	Devices         Devices         `json:"Devices"`
}

// ComputeTopology sizes the VM.
type ComputeTopology struct {
	Memory    struct{ SizeInMB int } `json:"Memory"`
	Processor struct{ Count int }    `json:"Processor"`
}

// Devices are the VM's devices: only the image's storage, never a NIC.
type Devices struct {
	Scsi map[string]any `json:"Scsi,omitempty"`
}

// Container is the run's container in the utility VM.
type Container struct {
	Owner           string        `json:"Owner"`
	SchemaVersion   SchemaVersion `json:"SchemaVersion"`
	HostingSystemID string        `json:"HostingSystemId"`
	Container       ContainerBody `json:"Container"`
}

// ContainerBody is the container's storage and mounts.
type ContainerBody struct {
	Storage           Storage           `json:"Storage"`
	MappedDirectories []MappedDirectory `json:"MappedDirectories"`
}

// Storage is the container's layers.
type Storage struct {
	Layers []Layer `json:"Layers"`
}

// Plan is one run's facts.
type Plan struct {
	RunID       string
	Layers      []Layer
	Workspace   string
	WorkspaceRO bool
	// ContainerWorkspace is where the workspace appears inside.
	ContainerWorkspace string
	// Protected are host paths mapped read-only at the same relative place.
	Protected []MappedDirectory
	MemoryMB  int
	CPUs      int
}

// Owner names every compute system Observer creates.
const Owner = "superbased-observer"

// UVMID and ContainerID name a run's compute systems.
func UVMID(runID string) string       { return "observer-uvm-" + runID }
func ContainerID(runID string) string { return "observer-sbx-" + runID }

// Build plans the two documents. It refuses a plan without layers or a
// workspace, a protected path mapped writable, or a container path that is
// not absolute.
func Build(p Plan) (UtilityVM, Container, error) {
	if p.RunID == "" || strings.ContainsAny(p.RunID, `\/:`) || len(p.Layers) == 0 || p.Workspace == "" || !strings.HasPrefix(p.ContainerWorkspace, `C:\`) {
		return UtilityVM{}, Container{}, fmt.Errorf("sandboxhcs: the plan needs a run id, image layers and a workspace mapped under C:\\")
	}
	mem, cpus := p.MemoryMB, p.CPUs
	if mem <= 0 {
		mem = 2048
	}
	if cpus <= 0 {
		cpus = 2
	}
	uvm := UtilityVM{Owner: Owner, SchemaVersion: SchemaVersion{2, MinSchemaMinor}, ShouldTerminateOnLastHandleClosed: true}
	uvm.VirtualMachine.StopOnReset = true
	uvm.VirtualMachine.ComputeTopology.Memory.SizeInMB = mem
	uvm.VirtualMachine.ComputeTopology.Processor.Count = cpus
	maps := []MappedDirectory{{HostPath: p.Workspace, ContainerPath: p.ContainerWorkspace, ReadOnly: p.WorkspaceRO}}
	for _, m := range p.Protected {
		if !m.ReadOnly {
			return UtilityVM{}, Container{}, fmt.Errorf("sandboxhcs: protected path %s must be read-only", m.HostPath)
		}
		if !strings.HasPrefix(m.ContainerPath, `C:\`) {
			return UtilityVM{}, Container{}, fmt.Errorf("sandboxhcs: protected path %s has no absolute container path", m.HostPath)
		}
		maps = append(maps, m)
	}
	c := Container{
		Owner: Owner, SchemaVersion: SchemaVersion{2, MinSchemaMinor}, HostingSystemID: UVMID(p.RunID),
		Container: ContainerBody{Storage: Storage{Layers: p.Layers}, MappedDirectories: maps},
	}
	return uvm, c, nil
}

// Marshal renders a document.
func Marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
