package secreachgo

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"io"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// Format is an executable's format as Inspect reads it.
type Format string

// The formats.
const (
	FormatELF     Format = "elf"
	FormatPE      Format = "pe"
	FormatMachO   Format = "macho"
	FormatUnknown Format = "unknown"
)

// Inspection is what Inspect found.
type Inspection struct {
	Format Format
	// Checkable: the binary keeps the symbol table naming the Go function
	// symbol and the Go line table, which govulncheck's binary mode needs
	// for function-level answers.
	Checkable bool
	// Reason is why it is not checkable (secreach.ReasonStripped,
	// secreach.ReasonUnsupportedBinary); "" when it is.
	Reason secreach.Reason
}

// The Go function symbol govulncheck looks up (go1.20 and later, then
// go1.18 and go1.19), and the symbol a Mach-O binary keeps unless it is
// stripped.
var goFuncSymbols = []string{"go:func.*", "go.func.*"}

const machoMustExist = "runtime.main"

// formatRow is one row of the format table: the header prefix at an offset,
// and the reader that decides checkability.
type formatRow struct {
	Format Format
	Prefix string
	Offset int
	Check  func(io.ReaderAt) bool
}

// formatRows mirrors the formats govulncheck's binary reader opens (ELF,
// PE, thin Mach-O); a universal Mach-O, WebAssembly or anything else is
// unsupported.
var formatRows = []formatRow{
	{FormatELF, "\x7fELF", 0, checkELF},
	{FormatPE, "MZ", 0, checkPE},
	{FormatMachO, "\xfe\xed\xfa", 0, checkMachO},
	{FormatMachO, "\xfa\xed\xfe", 1, checkMachO},
}

// stripped reads as "stripped" every way a binary can lose what
// govulncheck needs: no symbol table, no Go function symbol, no Go line
// table. Any read error counts as stripped: never a precise answer from a
// binary Observer could not read.
func stripped() Inspection { return Inspection{Reason: secreach.ReasonStripped} }

// Inspect reads the executable at r.
func Inspect(r io.ReaderAt) Inspection {
	head := make([]byte, 8)
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	for _, row := range formatRows {
		if len(head) < row.Offset+len(row.Prefix) || !bytes.Equal(head[row.Offset:row.Offset+len(row.Prefix)], []byte(row.Prefix)) {
			continue
		}
		out := stripped()
		out.Format = row.Format
		if row.Check(r) {
			out.Checkable, out.Reason = true, ""
		}
		return out
	}
	return Inspection{Format: FormatUnknown, Reason: secreach.ReasonUnsupportedBinary}
}

func hasGoFuncSymbol(names map[string]bool) bool {
	for _, s := range goFuncSymbols {
		if names[s] {
			return true
		}
	}
	return false
}

func checkELF(r io.ReaderAt) bool {
	f, err := elf.NewFile(r)
	if err != nil {
		return false
	}
	syms, err := f.Symbols()
	if err != nil || len(syms) == 0 {
		return false
	}
	names := make(map[string]bool, 4)
	for _, s := range syms {
		for _, want := range goFuncSymbols {
			if s.Name == want {
				names[want] = true
			}
		}
	}
	if !hasGoFuncSymbol(names) {
		return false
	}
	return f.Section(".gopclntab") != nil || f.Section(".data.rel.ro.gopclntab") != nil
}

func checkPE(r io.ReaderAt) bool {
	f, err := pe.NewFile(r)
	if err != nil || len(f.Symbols) == 0 {
		return false
	}
	names := map[string]bool{}
	for _, s := range f.Symbols {
		switch s.Name {
		case goFuncSymbols[0], goFuncSymbols[1], "runtime.pclntab", "runtime.epclntab":
			names[s.Name] = true
		}
	}
	return hasGoFuncSymbol(names) && names["runtime.pclntab"] && names["runtime.epclntab"]
}

func checkMachO(r io.ReaderAt) bool {
	f, err := macho.NewFile(r)
	if err != nil || f.Symtab == nil || len(f.Symtab.Syms) == 0 {
		return false
	}
	names := map[string]bool{}
	for _, s := range f.Symtab.Syms {
		switch s.Name {
		case goFuncSymbols[0], goFuncSymbols[1], machoMustExist:
			names[s.Name] = true
		}
	}
	return names[machoMustExist] && hasGoFuncSymbol(names) && f.Section("__gopclntab") != nil
}
