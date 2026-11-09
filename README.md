# Ghidra 12.1.4 + Rizin 0.9.1 Workspace

Linux x86_64 reverse-engineering workspace for ChatGPT Work and local use. **Ghidra and Rizin are independent analyzers**: use either tool on your own binaries without requiring a Ghidra/Rizin plugin.

## Clone

~~~bash
git clone --depth 1 https://github.com/Chaborsz/Ghidra-12.1.4-Workspace.git
cd Ghidra-12.1.4-Workspace
~~~

## Ghidra 12.1.4

The official Ghidra release is already extracted in `ghidra_12.1.4_PUBLIC/`. It requires JDK 21.

~~~bash
./ghidra_12.1.4_PUBLIC/support/analyzeHeadless
~~~

Official source: [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra), release `Ghidra_12.1.4_build`, archive `ghidra_12.1.4_PUBLIC_20260921.zip`.

Archive SHA-256: `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.

The existing `materialize-ghidra.yml` workflow verifies the official archive and its extracted tree.

## Rizin 0.9.1 (Linux x86_64)

Rizin uses the official **static** Linux release: no system installation or root permissions needed. A GitHub Actions workflow bundles its verified archive in `rizin_offline/v0.9.1-linux-x86_64/` as pieces below GitHub's 100 MiB file limit. On first use, the launcher verifies SHA-256 and expands it into a user cache; subsequent invocations reuse the installation. If the bundle has not yet been materialized, the launcher can fetch the **same pinned release** from upstream and verifies its hash.

~~~bash
./tools/rizin/rizin -v
./tools/rizin/rizin /absolute/path/to/file.exe
./tools/rizin/rz-bin -I /absolute/path/to/file.exe
./tools/rizin/rz-bin -zz /absolute/path/to/file.exe
./tools/rizin/analyze.sh /absolute/path/to/file.exe
./tools/rizin/analyze.sh --deep /absolute/path/to/file.exe /path/to/reports
~~~

`analyze.sh` creates `info.txt`, `sections.txt`, `strings.txt`, `functions.txt` and a SHA-256 file in the output directory. The default analysis is `aa`; use `--deep` for `aaa` on suitable binaries. For a quick interactive session, start `./tools/rizin/rizin FILE`, then enter `aa`, `afl`, `pdf @ main`, etc.

The `tools/rizin/launch.sh` entry point also accepts `rz-asm`, `rz-hash`, `rz-find`, `rz-diff`, and `rz-ax` (when included in the official archive). All arguments are passed through unchanged.

Official source: [rizinorg/rizin](https://github.com/rizinorg/rizin/releases/tag/v0.9.1), `rizin-v0.9.1-static-x86_64.tar.xz`.

Archive SHA-256: `9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf`.

Run [Materialize Rizin](https://github.com/Chaborsz/Ghidra-12.1.4-Workspace/actions/workflows/materialize-rizin.yml) if offline archive pieces are not present yet. The workflow validates the binaries and an actual headless analysis before publishing the pieces. The bundled files are for Linux x86_64 only (not Windows executables).

By default, the local extracted copy is under `~/.cache/ghidra-rizin-workspace/`; override the base directory with `RIZIN_WORKSPACE_CACHE`. No analyzed user file is committed into the repository.

## Integrity and scope

The two tools have independently pinned official sources and checksums. Ghidra's existing installation and APK2-specific workflows are not modified by Rizin provisioning.
