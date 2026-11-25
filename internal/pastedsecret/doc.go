// Package pastedsecret cleans a secret a person pasted at a terminal prompt
// or into a form: the one owner of that rule (live run 2026-11-19, defect D9,
// first written for `observer sandbox credentials add`; `observer sdk
// use-key` reads its key through it too). A terminal paste can carry the
// bracketed-paste markers (ESC[200~ before, ESC[201~ after) when the console
// has bracketed paste turned on, a CR or LF the clipboard held, a byte-order
// mark, or zero-width characters. Pure: no I/O, and nothing here ever returns
// or quotes more than the cleaned value it was given.
package pastedsecret
