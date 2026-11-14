---
name: Bug report
about: Something in Morpheus Certificate Install doesn't work
title: ''
labels: bug
---

<!-- morpheus-certificate-install 0.4.2. Security problems: see SECURITY.md, not an issue. -->

**Version**
<!-- The window's title bar, or `morpheus-certificate-install-cli --version` -->

**OS**
<!-- Windows 10/11, Linux (which distribution) or macOS (version, Apple Silicon or Intel); portable, installer, deb, rpm, AppImage or dmg -->

**Transport**
<!-- Convert only (no appliance) / SSH / Charon session (which tier) -->

**Morpheus / HPE VME version** (if it got as far as the appliance)

**What happened, and what you expected instead**

**Steps to reproduce**
1.
2.
3.

---

### Diagnostics

**Run log excerpt.** Copy from the Run log tab, around the failure.
Remove hostnames, addresses and anything secret first. The app never prints
passwords or the API token, but check anyway.

```
```

**If a conversion failed:** what kinds of files went in (for example "a .pfx
from Windows" or "a .p7b plus a PKCS#1 key"), and the checks the page showed.
Don't attach the certificate files or a private key.

**If a run on the appliance failed:** the end of its log on the appliance:

```bash
sudo tail -n 100 /var/log/morpheus-certificate-install/<run>.log
```

```
```
