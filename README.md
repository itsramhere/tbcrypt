# tbcrypt

## What it does

tbcrypt prepares private files for TeraBox and restores them afterward. Run it
from a terminal and use the page it opens in your browser. Choose your folders
for each job; no tray icon, background service, or watched folder is required.

For encryption, tbcrypt copies each file into a private staging folder, removes
supported embedded metadata if Exiftool is available, encrypts it into a `.tbx`
file, then decrypts and verifies the encrypted output. **Your originals stay in
place by default.** You can choose to move them into a `done` folder after
verification. Processing streams file contents with bounded memory.

Upload only your chosen **encrypted output folder**. TeraBox can still see
filenames, folder structure, approximate original sizes, file counts, and upload
times. Content and embedded metadata are encrypted. Metadata stripping removes
supported tags before encryption, while retaining orientation and colour
information to avoid rotated images and colour changes. If stripping is off or
fails, metadata is still protected by encryption and returns after decryption.

The tool protects uploaded content from someone without your keyfile and
password. It does not protect an unlocked or compromised computer, local
originals, temporary copies, or decrypted files. Keep plaintext folders outside
your cloud upload/sync selection.

## Build and install

Use Go 1.26.3 or newer on Windows:

```powershell
.\build.ps1
.\dist\tbcrypt.exe
```

The build runs vet and tests, then creates a console application at
`dist\tbcrypt.exe` with `CGO_ENABLED=0`. No C compiler or frontend build tools are
needed. If a running old copy prevents replacement, the script builds
`dist\tbcrypt-new.exe` and prints that filename instead.

To install it for your Windows user:

```powershell
.\install.ps1
```

The installer builds the application, copies it to
`%LOCALAPPDATA%\Programs\tbcrypt\tbcrypt.exe`, and adds that folder to your user
PATH if needed. Open a **new terminal** afterward and run `tbcrypt`. The
installer does not require administrator privileges under normal permissions.
This repository's automated checks do not run the installer or change PATH.

Exiftool is optional. Download it from [exiftool.org](https://exiftool.org/),
follow its Windows installation instructions, rename the executable to
`exiftool.exe`, and place it on PATH (keep any supplied supporting files with
it). Alternatively, set `exiftool_path` in the configuration file. The older
`exiftool(-k).exe` name is also detected on PATH. Without Exiftool, files are
still encrypted and the page shows a metadata-stripping notice.

## First run

Open PowerShell or another terminal and run:

```powershell
tbcrypt
```

tbcrypt listens on `127.0.0.1:8737` and opens your default browser. If that port
is busy, it tries 8738–8747. The terminal prints a private link like:

```text
tbcrypt running at http://127.0.0.1:8737/#<session-token> — press Ctrl+C to stop
```

Keep the terminal window open while using tbcrypt. Use Ctrl+C to stop the
server; running jobs are canceled and owned partial files are cleaned up. To
pick a different port or open the browser yourself:

```powershell
tbcrypt serve --port 8799 --no-browser
```

A custom port also falls back to its next ten ports if busy. Use the actual
URL printed by the terminal. `tbcrypt --no-browser` is accepted too.

On first run, create and confirm a password of at least 12 characters. Read the
keyfile warning, save a backup, and acknowledge that you need both the keyfile
and its password. On later launches, unlock your existing key with the password.
The app locks after 15 minutes without API activity when no job is running.
The **Lock** button cancels an active job, waits for cleanup, and locks the key.

## Encrypt a folder

1. Choose **Encrypt a folder**.
2. Choose the source folder, or paste its full path.
3. Choose where to save the encrypted files.
4. Leave the move-originals checkbox unchecked to keep your originals in place.
   Check it only if you want verified originals moved into `<source>\done`.
5. Select **Encrypt** and watch the progress. Cancel stops unfinished work;
   successfully completed files remain available.
6. When done, use **Open folder** and upload the contents of the encrypted
   output folder to TeraBox.

Nested paths are mirrored. The output folder may be inside the source folder;
it is excluded from scanning, along with `done` when moving originals, the private staging folder,
temporary files, hidden Windows files, and existing `.tbx` files. Source and
output cannot be the same folder, and the output cannot contain the source.
Originals cannot be archived into the encrypted output folder.

Plaintext staging uses the hidden `<source>\.tbcrypt-tmp` folder, outside the
upload directory. Owned crash leftovers are cleaned at the start of a new
encryption job. Existing output files are preserved using numbered names such
as `photo (2).jpg.tbx`.

## Decrypt files

Download your `.tbx` containers from TeraBox, unlock tbcrypt, then:

1. Choose **Decrypt files**.
2. Use **Choose files…** for one or more containers, or **Choose folder…** for a
   recursive restore. You can also paste full paths, one per line.
3. Choose a destination folder on your computer.
4. Select **Decrypt**. Folder restores mirror the input tree. Use **Open folder**
   when finished.

Only `.tbx` files are selected during directory scans. Authentication failures,
wrong keys, tampering, truncation, trailing data, and incorrect decrypted sizes
are rejected. Plaintext is written to `.part`, fsynced, and published only after
complete authentication. Errors and cancellation remove owned partial outputs.
Existing restored files receive numbered names instead of being overwritten.

## Back up your keyfile AND password

**Losing either `keyfile.json` or its password means permanent data loss.**
The password alone cannot reconstruct your key. The keyfile alone cannot unlock
it. There is no reset or recovery service for encrypted files.

Use **Save keyfile backup** to export the keyfile to a USB drive, password
manager, or another safe location. Keep its password safe too. Do not store the
keyfile alongside the files you upload to TeraBox. Export refuses to overwrite
an existing backup.

**Change password** rewraps the same identity, so existing containers still
decrypt. Save a fresh backup afterward: older backups retain the password that
was in effect when they were exported.

## Local web security

The server binds IPv4 loopback only. It requires a random 32-byte session token
on every API request, rejects unexpected Host and Origin headers, enables no
CORS access, and serves a Content Security Policy that allows only local assets.
The page contains no CDN assets, analytics, or automatic external requests.
The optional Exiftool link opens its website only when you choose it.

The token arrives in the URL fragment, which is not sent to the HTTP server or
in referrers. The page remembers it in session storage for reloads, removes it
from the visible URL, and sends it in a request header. The token changes on
each launch. Use the complete newly printed URL after restarting; keep this
private session link to yourself. Passwords are not logged or saved by the page.
The unlocked identity remains in process memory until locking or shutdown; Go
does not guarantee erasure of all copies in managed memory.

One job runs at a time. The last 20 jobs and their per-file results are held in
memory for the session. Job data is discarded when the server exits. **Open
folder** only opens directories that were used by a job in the current session.

## Configuration

`config.json` and `keyfile.json` live in `%APPDATA%\tbcrypt` on Windows (the Go
user configuration directory elsewhere). `TBCRYPT_HOME` overrides that folder.
Both the web UI and CLI log to the terminal; the web UI shows per-file warnings
and errors on the page.

| Field | Purpose |
| --- | --- |
| `exiftool_path` | Optional executable path; otherwise PATH lookup is used. |
| `last_encrypt_src` | Most recent browser encryption source folder. |
| `last_encrypt_out` | Most recent browser encrypted output folder. |
| `last_decrypt_src` | Most recent browser restore source folder. |
| `last_decrypt_out` | Most recent browser restore destination. |
| `watch_dir`, `output_dir`, `done_dir` | Retained for the headless CLI. The web UI chooses its folders per job. |

Empty CLI output/archive fields resolve to `encrypted`/`done` beneath its input
folder. The legacy `start_with_windows` field is ignored. The tray and autostart
integration have been removed; this upgrade does not alter any Windows startup
registration left by an older version.

## CLI reference

```text
tbcrypt                                    Start the browser interface
tbcrypt serve [--port N] [--no-browser]      Start the local server explicitly
tbcrypt init                               Create a key from the terminal
tbcrypt export <dest>                      Export a keyfile backup
tbcrypt passwd                             Change the keyfile password
tbcrypt encrypt <dir> [-o dir] [-done dir] [-exiftool path]
tbcrypt watch <dir> [-o dir] [-done dir] [-exiftool path]
tbcrypt encrypt-file <file> [-o dir] [-exiftool path]
tbcrypt decrypt <file.tbx|dir> [-o dir]
tbcrypt help
```

`encrypt` scans once, verifies encrypted outputs, then archives originals.
`encrypt-file` verifies a single file and retains its original. `decrypt`
defaults to `.\decrypted`. Flags may appear before or after a file command's
input path. CLI passwords require a terminal, or `TBCRYPT_PASSWORD` for
unattended use. `passwd` also accepts `TBCRYPT_NEW_PASSWORD`. The browser UI
always uses the password entered on its page.

The headless `watch` command remains available for automation. It waits for
three seconds of stable size/mtime, checks Windows file sharing, uses one
worker, and retries failures after 10 seconds, one minute, and five minutes.
The browser UI runs explicit jobs and does not use the watcher.

## Limitations

- TeraBox cannot preview `.tbx` content. Restoring on mobile still needs this
  tool, the keyfile, and the password; no mobile app is included.
- Metadata removal depends on Exiftool and format support. Orientation and
  colour information are intentionally retained.
- Local deletion does not guarantee secure erasure on SSDs, snapshots, or backups.
  Keep the staging directory and plaintext originals out of cloud sync.
- The process must stay running while you use the page. Forced process kills or
  power loss can leave owned `.part` or staging files; normal errors and graceful
  cancellation clean them up. Completed job outputs are retained after canceling.
- Native pickers use zenity's Windows dialogs. Other platforms may require its
  supported dialog helpers; editable path boxes work without native pickers.

## Development checks

No frontend build step is required: HTML, CSS, and vanilla JavaScript are
embedded in the Go executable. Containers use age X25519; keyfiles use Argon2id
and secretbox. No custom crypto primitives are used. The shared restore planner
is used by both the CLI and web jobs. Files are enumerated before restoration,
so newly restored outputs are never reprocessed by that job.

```powershell
gofmt -l .
go vet ./...
$env:GOOS = 'linux'; go vet ./...; Remove-Item Env:GOOS
go test -count=1 ./...
.\build.ps1
```

Tests use an injectable picker and light Argon2 work factors where appropriate.
They do not open native dialogs. The actual Exiftool test skips when Exiftool
is absent. The installer is intentionally excluded from automated execution.
