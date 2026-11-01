// Command observerw is the no-console twin of observer.exe on Windows, the
// way pythonw.exe is to python.exe: `observerw.exe <args>` runs the
// observer.exe beside it with the same arguments and no console window.
//
// It exists for two callers that would otherwise flash a console at the
// user: the start-at-sign-in entry (HKCU\...\Run, written by `observer setup
// autostart on`) and the Start menu shortcut the Windows setup program
// creates. Both run `observerw.exe setup launch [--open]`. It is built with
// `-H windowsgui` in the release workflow's windows_setup job and ships only
// inside the setup program.
//
// It holds no logic of its own: every decision stays in observer.exe
// (`observer setup launch`), so there is nothing here to drift.
package main
