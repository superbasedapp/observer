package sandboxseccomp

import (
	"encoding/binary"
	"fmt"
)

// seccompData is a synthetic struct seccomp_data.
type seccompData struct {
	nr   uint32
	arch uint32
	args [6]uint64
}

// bytes renders it in the kernel's little-endian layout.
func (d seccompData) bytes() []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:], d.nr)
	binary.LittleEndian.PutUint32(b[4:], d.arch)
	for i, a := range d.args {
		binary.LittleEndian.PutUint64(b[16+8*i:], a)
	}
	return b
}

// run interprets a program over d the way the kernel's seccomp BPF checker
// and interpreter do for the subset the assembler emits: absolute word
// loads inside seccomp_data, forward K jumps, and K returns. Anything else
// is an error, so a program the kernel would refuse fails here too.
func run(p Program, d seccompData) (uint32, error) {
	data := d.bytes()
	var acc uint32
	for pc := 0; pc < len(p); pc++ {
		in := p[pc]
		switch in.Code {
		case opLdAbsW:
			if in.K%4 != 0 || int(in.K)+4 > len(data) {
				return 0, fmt.Errorf("pc %d: load at %d is outside seccomp_data", pc, in.K)
			}
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case opJeqK, opJsetK:
			hit := acc == in.K
			if in.Code == opJsetK {
				hit = acc&in.K != 0
			}
			off := int(in.JF)
			if hit {
				off = int(in.JT)
			}
			if pc+1+off >= len(p) {
				return 0, fmt.Errorf("pc %d: jump past the end", pc)
			}
			pc += off
		case opRetK:
			return in.K, nil
		default:
			return 0, fmt.Errorf("pc %d: opcode %#x", pc, in.Code)
		}
	}
	return 0, fmt.Errorf("the program fell off its end")
}

// actionOf names a return value.
func actionOf(ret uint32) Action {
	switch {
	case ret == retAllow:
		return ActionAllow
	case ret == retKillProcess:
		return ActionKill
	case ret&^retDataMask == retErrno && ret&retDataMask == errnoEPERM:
		return ActionErrno
	}
	return Action(fmt.Sprintf("unknown_%#x", ret))
}
