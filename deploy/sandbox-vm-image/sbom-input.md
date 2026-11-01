# SBOM input of the microVM guest image set

The SBOM (`sandbox-vm.spdx.json`, SPDX 2.3) is generated, never written by
hand: `vendorsign sandboxrootfs` reads `build/packages.tsv` (one line per
installed rootfs package: name, version, architecture, from `dpkg-query`
inside the build) and `build/kernel.tsv` (the kernel package, its version
and its deb's sha256) and renders the set as the described package, the
kernel as a contained package and every rootfs package as a contained
package (`sandboximage.VMSPDX`). A package that is an agent CLI is refused
there, as the build's own hook refuses one in the rootfs.
