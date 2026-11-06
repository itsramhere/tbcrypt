# tbcrypt

## What it does and threat model

tbcrypt is a Windows tray application and CLI for preparing private files for
TeraBox. It makes a temporary copy, removes supported embedded metadata with
Exiftool, encrypts the copy into a `.tbx` container, decrypts and verifies its
SHA-256/name/size, then moves the original into `done\`. The originals are never
modified by Exiftool. Encryption streams files with bounded memory.

Upload **only `encrypted\`**, which contains the encrypted containers. TeraBox
can still see container filenames (including the original filename), approximate
content sizes, folder structure, file counts, and upload times. File content and
its embedded metadata are encrypted. When Exiftool is installed and supports the
format, removable metadata is also stripped before encryption. Orientation and
colour information are preserved to avoid rotated images and colour changes.
Exiftool failures produce warnings and encryption continues with an unstripped
copy: metadata remains encrypted, but will reappear when that file is decrypted.

This protects uploaded content from someone who lacks your private key and
password. It does not protect an unlocked computer, plaintext originals,
`done\`, decrypted files, or temporary copies on the local disk. Filesystem
timestamps and filenames are not anonymized. Use a trusted local watch folder;
keep `done\` and `.tbcrypt-tmp\` outside any cloud upload/sync selection.

## Install

Use Go 1.26.3 or newer on Windows:

```powershell
.\build.ps1
```

The script runs vet and tests, then builds `dist\tbcrypt.exe` with cgo disabled
and the Windows GUI subsystem. Copy that executable to a permanent location
before enabling **Start with Windows**. No C compiler is needed. To build a
console-subsystem executable while developing:

```powershell
$env:CGO_ENABLED = '0'
go build -o tbcrypt.exe ./cmd/tbcrypt
```

Metadata removal is optional. Download Exiftool from
[exiftool.org](https://exiftool.org/), follow its Windows installation instructions
(including keeping its supporting files together), rename the Windows executable
to `exiftool.exe`, and add its folder to PATH. Alternatively, set its full path
in `config.json` as `exiftool_path`. `exiftool(-k).exe` on PATH is also detected.
Without Exiftool, the app warns once per session and encrypts unstripped copies.

## First run

Launch `tbcrypt.exe` with no arguments. The tray wizard asks you to create and
confirm a password of at least 12 bytes, offers a keyfile backup, then asks for a
watch folder. Subsequent launches ask for the password to unlock the same key.
Canceling exits; an existing key allows five unlock attempts per launch. A
session mutex prevents a second tray instance.

Configuration and keys live in `%APPDATA%\tbcrypt`. `TBCRYPT_HOME` overrides this
location. The tray log is `tbcrypt.log` there, rotating at 5 MiB with three
backups. CLI logs go to stderr.

## Daily use

1. Drop files or folders into your watch folder.
2. The watcher waits until each file's size and modification time are unchanged
   for three seconds and Windows permits opening it without a writer sharing it.
3. Files are stripped, encrypted, verified, and their originals moved into the
   matching path under `done\`.
4. When the batch is ready, upload the **`encrypted\` folder only** to TeraBox.

You can pause/resume processing, choose another watch folder, open folders or
logs, export the keyfile, change the password, and enable startup from the tray
menu. Pause retains the queue and lets the current file finish. Watcher failures
retry after 10 seconds, one minute, and five minutes (four attempts total), then
report a failure and leave the source untouched. A later change to a failed
file makes it eligible again; restarting also performs a catch-up scan.

Nested paths are mirrored. Collisions use numbered names such as
`photo (2).jpg.tbx` and `photo (2).jpg`; existing files are preserved. Temporary
plaintext is staged in the hidden `<watch folder>\.tbcrypt-tmp`, never inside
the encrypted output folder. Startup removes owned crash leftovers there.
Quit cancels processing and waits up to ten seconds for the watcher to stop.

## Restoring

Download the `.tbx` containers, unlock tbcrypt, then choose **Decrypt files…**
for one or more containers or **Decrypt folder…** for a recursive restore.
Choose a destination folder. Folder restores mirror the downloaded tree, and
existing restored files get numbered names.

You can also restore from PowerShell:

```powershell
.\tbcrypt.exe decrypt C:\Downloads\photo.jpg.tbx -o C:\Restored
.\tbcrypt.exe decrypt C:\Downloads\encrypted -o C:\Restored
```

Wrong keys, authentication failures, truncation, trailing data, and incorrect
decrypted sizes are rejected. Plaintext is written to `.part` and only published
after complete authentication; owned partial files are removed on errors.

## Back up your keyfile AND password

**Losing either `keyfile.json` or its password means permanent data loss.**
The password alone cannot reconstruct the key; the keyfile alone cannot unlock
it. There is no recovery service or reset that can decrypt existing files.

Use **Export keyfile…** or `tbcrypt export` to make a backup on a USB drive or
in a password manager. Keep the password safely too. Do not place the keyfile in
the TeraBox upload folder alongside your files. Export refuses to overwrite an
existing backup. Changing the password preserves the encryption identity, so
old containers still decrypt. Re-export afterward: older backups still require
the password they had when exported.

## Configuration

`config.json` uses JSON with these fields (paths shown with JSON escaping):

```json
{
  "watch_dir": "C:\\Users\\you\\PrivateInput",
  "output_dir": "",
  "done_dir": "",
  "exiftool_path": "C:\\Tools\\exiftool\\exiftool.exe",
  "start_with_windows": false
}
```

| Field | Meaning |
| --- | --- |
| `watch_dir` | Recursive input folder selected by the tray; CLI input overrides it. |
| `output_dir` | Empty uses `<watch_dir>\encrypted`; otherwise an explicit output folder. |
| `done_dir` | Empty uses `<watch_dir>\done`; otherwise an explicit archive folder. |
| `exiftool_path` | Full executable path; absent/unavailable paths fall back to PATH lookup. |
| `start_with_windows` | Synced with the current user's Windows startup entry by the tray. Use its checkbox to change it. |

Choosing another watch folder recomputes default output/archive locations.
Explicit configured locations remain in effect. Startup registration uses a
quoted executable path in the current user's `Run` registry key; administrator
access is not required under normal Windows permissions. Move the executable
after registration only if you disable and re-enable startup afterward.

The reusable pipeline also accepts an explicit `Options.TempDir`. It defaults
to `.tbcrypt-tmp` in the watch folder; paths resolving into `OutputDir` are
rejected. `CleanTemp` is a startup operation and must not run concurrently with
processing in that directory. The staging directory cannot be the watch folder
or its ancestor, and plaintext archives cannot be placed inside `output_dir`.

## CLI reference

```text
tbcrypt init
tbcrypt export <dest>
tbcrypt passwd
tbcrypt encrypt <dir> [-o outdir] [-done archive] [-exiftool executable]
tbcrypt watch <dir> [-o outdir] [-done archive] [-exiftool executable]
tbcrypt encrypt-file <file> [-o outdir] [-exiftool executable]
tbcrypt decrypt <file.tbx|dir> [-o outdir]
tbcrypt help
```

`encrypt` scans once and archives originals after verification. `watch` stays
active until Ctrl+C and includes an initial catch-up scan. `encrypt-file` strips
and verifies a single file while retaining its original. `decrypt` defaults to
`.\decrypted`. Flags may appear before or after the input path.

Passwords are prompted without echo on a terminal. For unattended use,
`TBCRYPT_PASSWORD` supplies the current password; `passwd` additionally accepts
`TBCRYPT_NEW_PASSWORD`. Piped plaintext password input is not accepted. The GUI
release attaches to its parent console for CLI commands and preserves redirected
standard streams.

## Limitations

- TeraBox cannot preview `.tbx` content. Mobile devices need this tool (and the
  keyfile and password) to decrypt it; there is no mobile app in this milestone.
- Metadata removal depends on Exiftool and format support. Orientation and colour
  profiles are intentionally retained. Unsupported files are still encrypted.
- Local plaintext temporary files are removed normally and cleaned after crashes;
  deletion does not guarantee secure erasure on SSDs or backups.
- The tray and autostart require Windows. Core packages and the headless CLI
  compile on Linux; Windows file-sharing checks use a regular read-open there.
- Quit's ten-second limit cannot guarantee cleanup after a forced process kill or
  power loss. Keep the plaintext staging folder out of cloud sync.

## Development and verification

Application state is injected through contexts, options, keys, and loggers. The
watcher uses fsnotify with one worker, a deduplicated ready-file queue, bounded
retries, thread-safe status, and a best-effort buffered event stream. Containers
use age X25519; passwords protect the identity with Argon2id and secretbox. No
custom cryptographic primitives are used.

```powershell
gofmt -l .
go vet ./...
$env:GOOS = 'linux'; go vet ./...; Remove-Item Env:GOOS
go test -count=1 ./...
go test -count=3 ./internal/watcher/...
.\build.ps1
.\dist\tbcrypt.exe help
```

Tests use temporary directories and light Argon2 parameters where applicable.
The Exiftool integration test skips when it is absent. The isolated startup
registry test uses a unique test value and cleans it up; it skips if sandbox
permissions deny HKCU writes. Tray dialogs require an interactive Windows session
and are not launched by tests. Regenerate the embedded 16/32-pixel icon with
`go run ./tools/genicon` from the repository root.
