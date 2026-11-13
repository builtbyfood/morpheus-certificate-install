# charon-ssh

SSH transport, PTY sessions and host-key TOFU, extracted from charon so other
applications can share one implementation. hvm-desk depends on it for its
appliance operations.

Deliberately free of tauri, rusqlite, serialport and portable-pty: output
reaches a UI over plain channels, and an unknown host key is put to the user
through the `HostKeyPolicy` trait, so each application decides both for
itself.

`SshSession::exec_stdin` exists so a password can reach `sudo -S` on stdin
without ever appearing on a command line.

Apache-2.0 — see [LICENSE](LICENSE).
