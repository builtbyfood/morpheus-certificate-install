# Click tests — morpheus-certificate-install 0.4.2

The real app (the debug build), driven through its page the way a user drives it: real mouse clicks and typing, files chosen in the page's own file input, confirm dialogs answered by clicking their buttons. It runs on Windows, over the Chrome DevTools Protocol that WebView2 exposes when it's started with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<port>`. It's plain Node (22 or later): no browser download and no npm packages.

```powershell
npm run test:click                                # every default suite; the fake-VM ones skip without MCI_TEST_SSH
npm run test:click -- convert wildcard            # only these (a name or a name prefix)
$env:MCI_TEST_SSH = "<vm>:2222:mcitest:hunter2"; npm run test:click
$env:MCI_TEST_SSH = "<vm>:2222:mcitest:hunter2"; npm run test:click -- screenshots   # rewrites docs/screenshots/
```

`run.mjs` builds the debug exe first (`cargo build -p morpheus-certificate-install`; set `MCI_CLICK_NO_BUILD=1` to skip that). The app's window appears on screen while a suite runs; leave it alone.

## How a suite runs

- **A fresh portable folder per suite.** `<temp>/mci-click-<pid>/<suite>/app/` gets a copy of the debug exe and an empty `portable.flag`. Settings, `known_hosts` and the WebView2 profile then all land in that folder's `data/`, so suites never share them. The whole temp folder is removed at the end (`MCI_CLICK_KEEP=1` keeps it).
- **The page is read, not changed.** The harness records the `mci` events and each toast, and reads the DOM and the Run log's buffer. The one exception is the screenshot suite, which swaps lab names for example names just for each capture.
- **Browser errors fail the suite.** A CSP violation or an uncaught exception logged by the page fails the suite it happened in, even when its assertions passed.
- **The fake VM** (`docs/FAKE-APPLIANCE.md`) is checked over a second, independent SSH connection: `src-tauri/tests/click_ref.rs`, run by `lib/vm.mjs` with the script in `MCI_CLICK_REF`. That script text is test-only and lives in `lib/vm.mjs` and the suites.

## The test-only hook

Debug and test builds read one environment variable that release builds don't have (it's compiled out with `debug_assertions`):

- `MCI_TEST_SAVE_DIR=<dir>`: "Download files for Morpheus (.zip)" writes `<dir>/<name>.zip` without the save dialog.

Nothing else skips a confirmation. The suite `release-hooks` builds the release exe and checks that the name is in the debug exe and absent from the release exe.

## Suites

| Suite | Needs | What it clicks and checks |
|---|---|---|
| `convert` | — | corpus `chain.p7b` + `leaf-pkcs1.key`: three seals in order, the input table, Trust ticked with the private-CA reason, the zip's exact file list (key 0600). Lifetime bars and the Run log's colours take effect (no CSP block). |
| `wildcard` | — | wildcard leaf with no connection: the FQDN is asked for, and export stays blocked for no name, `*.wild.test` and an uncovered name; a covered name exports `morpheus_wild_test.*`. |
| `public-chain` | — | the private chain ticks Trust; Clear files resets it; the Go Daddy G2 root alone (no leaf) leaves it unticked, "Publicly trusted". |
| `errors-and-watch` | — | empty input and a rejected command show toasts; a bad PFX password shows on the file's row and as an error check; the watch bar stays hidden. |
| `vm-install` | VM | connect with the TOFU dialog → plan → install (confirm dialog) → watch bar → verify green → rollback to this install's backup; the VM is checked over the reference connection before and after. |
| `vm-hostkey-mismatch` | VM | `known_hosts` pre-seeded with wrong keys for the VM (the VM's real key is never rotated): refused with a toast, no dialog, file untouched; then "Forget this appliance" and Connect asks about the key afresh. |
| `vm-cleanup` | VM | a runner-shaped run that sleeps 75 s is started on the VM; "Clean up this appliance" with its defaults keeps that run's script and log and removes the finished runs and all backups but the newest. |
| `leave-no-trace` | (VM optional) | portable "Leave no trace" on, connected when `MCI_TEST_SSH` is set; closing the window (WM_CLOSE) deletes `data/`. Then with a file in `data/` held open: the exit leaves a marker; the next start deletes the folder and says so. |
| `release-hooks` | — | builds the release exe; `MCI_TEST_SAVE_DIR` is absent from it. |
| `screenshots` | VM, opt-in | `docs/screenshots/{connect,chain,plan,run,verify,cleanup}.png` at 1320×860, light theme, corpus certificates; checked against `.private-denylist` before writing; leaves the VM rolled back and cleaned up. |

The fake-VM suites change the VM's `/etc/morpheus` and the tool's own state on it, and put it back: they reset it to the starting state first, roll back and clean up.

## Not covered here

- **Linux** (webkit2gtk has no CDP). The suites are Windows-only for now.
- **The Charon transport.** Driving a real Charon session needs the maintainer to choose the session and tier first, since it drives whatever that session is connected to; the engine e2e covers it.
