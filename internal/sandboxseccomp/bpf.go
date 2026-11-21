package sandboxseccomp

import (
	"encoding/binary"
	"fmt"
)

// Instruction is one classic BPF instruction, the layout of the kernel's
// struct sock_filter (code, jt, jf, k).
type Instruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// InstructionSize is sizeof(struct sock_filter).
const InstructionSize = 8

// MaxInstructions is BPF_MAXINSNS, the kernel's program length limit.
const MaxInstructions = 4096

// The classic BPF opcodes the assembler emits (linux/bpf_common.h).
const (
	opLdAbsW    = 0x20 // BPF_LD | BPF_W | BPF_ABS
	opJeqK      = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	opJsetK     = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	opRetK      = 0x06 // BPF_RET | BPF_K
	opClassMask = 0x07 // BPF_CLASS mask
	classRet    = 0x06 // BPF_RET
)

// The seccomp return values (linux/seccomp.h).
const (
	retKillProcess = 0x80000000
	retErrno       = 0x00050000
	retAllow       = 0x7fff0000
	// retDataMask is SECCOMP_RET_DATA, where an errno rides.
	retDataMask = 0x0000ffff
	// errnoEPERM is EPERM.
	errnoEPERM = 1
)

// The struct seccomp_data offsets: nr (int), arch (u32), then ip (u64) and
// args[6] (u64 each). Both targets are little-endian, so the low half of
// argument 0 sits at 16.
const (
	offNr      = 0
	offArch    = 4
	offArg0Low = 16
)

// Program is an assembled filter.
type Program []Instruction

// Bytes renders the program as the kernel reads it: the struct sock_filter
// array in little-endian order (both targets are little-endian), the form
// `bwrap --seccomp <fd>` reads from its descriptor.
func (p Program) Bytes() []byte {
	out := make([]byte, len(p)*InstructionSize)
	for i, in := range p {
		b := out[i*InstructionSize:]
		binary.LittleEndian.PutUint16(b[0:], in.Code)
		b[2], b[3] = in.JT, in.JF
		binary.LittleEndian.PutUint32(b[4:], in.K)
	}
	return out
}

// DecisionKind is what a decision row matches.
type DecisionKind string

// The closed DecisionKind vocabulary, in program order.
const (
	// MatchForeignArch: seccomp_data.arch is not the target's native ABI.
	MatchForeignArch DecisionKind = "foreign_arch"
	// MatchX32: the syscall number carries __X32_SYSCALL_BIT (amd64 only).
	MatchX32 DecisionKind = "x32_abi"
	// MatchSyscall: one profile row.
	MatchSyscall DecisionKind = "syscall"
	// MatchDefault: anything no row matched.
	MatchDefault DecisionKind = "default"
)

// Decision is one row of the per-architecture decision table, walked top
// down by the assembled program.
type Decision struct {
	Kind    DecisionKind
	Syscall string
	Nr      uint32
	Arg0In  []uint32
	Action  Action
}

// Decisions derives the decision table of a profile on goarch: the foreign
// architecture row, the x32 row on amd64, one row per profile row that
// applies to goarch, then the default allow.
func Decisions(id ProfileID, goarch string) ([]Decision, error) {
	spec, ok := archs[goarch]
	if !ok {
		return nil, fmt.Errorf("sandboxseccomp: architecture %q is not supported (amd64 and arm64 are)", goarch)
	}
	rs, ok := profiles[id]
	if !ok {
		return nil, fmt.Errorf("sandboxseccomp: unknown profile %q", id)
	}
	if err := validate(rs, goarch, spec); err != nil {
		return nil, err
	}
	out := []Decision{{Kind: MatchForeignArch, Action: ActionKill}}
	if spec.x32Bit != 0 {
		out = append(out, Decision{Kind: MatchX32, Action: ActionKill})
	}
	for _, r := range rs {
		if !r.appliesTo(goarch) {
			continue
		}
		out = append(out, Decision{Kind: MatchSyscall, Syscall: r.Syscall, Nr: spec.nr[r.Syscall], Arg0In: append([]uint32(nil), r.Arg0In...), Action: r.Action})
	}
	return append(out, Decision{Kind: MatchDefault, Action: ActionAllow}), nil
}

// Build assembles profile id for goarch.
func Build(id ProfileID, goarch string) (Program, error) {
	ds, err := Decisions(id, goarch)
	if err != nil {
		return nil, err
	}
	return assemble(ds, archs[goarch])
}

// retFor is the return instruction of an action.
func retFor(a Action) (Instruction, error) {
	switch a {
	case ActionAllow:
		return Instruction{Code: opRetK, K: retAllow}, nil
	case ActionErrno:
		return Instruction{Code: opRetK, K: retErrno | errnoEPERM}, nil
	case ActionKill:
		return Instruction{Code: opRetK, K: retKillProcess}, nil
	}
	return Instruction{}, fmt.Errorf("sandboxseccomp: unknown action %q", a)
}

// skip is a forward jump distance, refused past the 8-bit field.
func skip(n int) (uint8, error) {
	if n < 0 || n > 255 {
		return 0, fmt.Errorf("sandboxseccomp: jump of %d instructions does not fit", n)
	}
	return uint8(n), nil
}

// assemble walks the decision table into a program. Every match is a
// conditional jump over its own return, so no jump crosses more than one
// row and the program's shape is the table's.
func assemble(ds []Decision, spec archSpec) (Program, error) {
	var p Program
	emit := func(in ...Instruction) { p = append(p, in...) }
	for _, d := range ds {
		ret, err := retFor(d.Action)
		if err != nil {
			return nil, err
		}
		switch d.Kind {
		case MatchForeignArch:
			emit(Instruction{Code: opLdAbsW, K: offArch},
				Instruction{Code: opJeqK, JT: 1, K: spec.audit},
				ret,
				Instruction{Code: opLdAbsW, K: offNr})
		case MatchX32:
			if spec.x32Bit == 0 {
				return nil, fmt.Errorf("sandboxseccomp: an x32 row on an architecture without the x32 ABI")
			}
			emit(Instruction{Code: opJsetK, JF: 1, K: spec.x32Bit}, ret)
		case MatchSyscall:
			if len(d.Arg0In) == 0 {
				emit(Instruction{Code: opJeqK, JF: 1, K: d.Nr}, ret)
				continue
			}
			jf, err := skip(2*len(d.Arg0In) + 2)
			if err != nil {
				return nil, err
			}
			allow, _ := retFor(ActionAllow)
			emit(Instruction{Code: opJeqK, JF: jf, K: d.Nr}, Instruction{Code: opLdAbsW, K: offArg0Low})
			for _, v := range d.Arg0In {
				emit(Instruction{Code: opJeqK, JF: 1, K: v}, ret)
			}
			// The syscall appears once (validate), so a value no row
			// refuses is allowed here; the accumulator no longer holds nr.
			emit(allow)
		case MatchDefault:
			emit(ret)
		default:
			return nil, fmt.Errorf("sandboxseccomp: unknown decision kind %q", d.Kind)
		}
	}
	if len(p) == 0 || len(p) > MaxInstructions {
		return nil, fmt.Errorf("sandboxseccomp: program of %d instructions (limit %d)", len(p), MaxInstructions)
	}
	if last := p[len(p)-1]; last.Code&opClassMask != classRet {
		return nil, fmt.Errorf("sandboxseccomp: the program does not end in a return")
	}
	return p, nil
}
