# T2 PS FIDO2 Manager

Manage FIDO2 security keys from Windows — set and change the PIN, inspect and delete resident credentials, adjust key policy, and enrol or remove fingerprints — using **pure PowerShell**.

It relies only on standard Windows DLLs (`hid.dll`, `setupapi.dll`, `kernel32.dll`, `winscard.dll`). **No modules, no libfido2, no drivers, nothing else to install.** The only requirement beyond Windows itself is administrator rights.
 

---

## Requirements

- **Windows** with **Windows PowerShell 5.1** (built in) or **PowerShell 7+**.
- **Administrator rights.** Everything except reading the serial number needs an elevated session.
- A FIDO2 key, connected by **USB** or presented on an **NFC reader**.

There is nothing to install. No NuGet packages, no PowerShell modules, no third-party libraries. The script calls the same Windows components that Windows itself uses for smart cards and HID devices.

---

## Quick start

1. Download `T2-PS-FIDO2-Manager.ps1` from the repository.
2. Open **PowerShell as Administrator** (right-click → *Run as administrator*).
3. Change to the folder where you saved the script.
4. Allow the script to run for this session, then launch the graphical interface:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\T2-PS-FIDO2-Manager.ps1 -Gui
```

`Set-ExecutionPolicy -Scope Process` affects only the current window and reverts when you close it; it does not change any machine-wide setting.

If Windows shows a *Security warning* about running a script from the internet, either choose **[R] Run once**, or unblock the file once beforehand:

```powershell
Unblock-File .\T2-PS-FIDO2-Manager.ps1
```

---

## Why administrator rights

FIDO operations touch the device at a level Windows guards:

- **CTAP over USB-HID** — opening the key's HID interface for read/write returns `ACCESS_DENIED` to a non-elevated process.
- **CTAP over NFC** — the PC/SC applet SELECT returns `SCARD_E_INSUFFICIENT_BUFFER` (`0x80100027`) without elevation.
- **Serial number** — the one exception; it uses a Token2 APDU and works **without** admin. Not applicable to non-Token2 FIDO2 keys

Run unelevated and the tool still starts: it reads the serial, warns that the rest needs admin, and continues. It never tries to elevate itself.

---

## Transports

The key can be reached two ways, and they carry different things:

| Transport | Via | Carries CTAP2? | Carries serial / vendor config? |
|-----------|-----|:---:|:---:|
| **HID** | `setupapi.dll` + `hid.dll` (USB only) | Yes | No |
| **CCID** | `winscard.dll` (PC/SC, USB **or** NFC) | Only over **NFC** | Yes |

Notes:

- A Token2 key on **USB** exposes *both* a HID interface and a USB-CCID interface. The USB-CCID side is serial/config only — it answers `6D00` / `6985` to CTAP2 and cannot carry it. CTAP2 there goes over **HID**.
- Over **NFC**, CCID does carry CTAP2.
- The serial number and vendor config are a CCID-only vendor command; the HID interface cannot read them.

`-Transport auto` (the default) prefers HID when elevated, otherwise CCID. Force one with `-Transport hid` or `-Transport ccid`.

In the graphical interface, when a USB HID key is present, its redundant USB-CCID entry is hidden from the device list to avoid confusion; the serial and vendor config are still read from it behind the scenes.

---

## Graphical interface

```powershell
.\T2-PS-FIDO2-Manager.ps1 -Gui
```

Tabs:

- **Info** — serial, CTAP2 `getInfo`, and vendor config.
- **Credentials** — list and delete resident credentials (passkeys).
- **PIN** — check the retry counter, set or change the PIN.
- **Fingerprints** — sensor info, list, enrol (with a live touch dialog), rename, and delete. Enrolment can be cancelled mid-way.
- **Policy** — `alwaysUv`, minimum PIN length, force PIN change.
- **Reset** — factory reset (wipes every passkey and the PIN).
- **About** — version, links, and copyright.

You can tick **Remember for this session** at the PIN prompt to avoid retyping it. The PIN is held **in memory only for the lifetime of the window** — it is never written to disk — and is cleared on rescan or if the key rejects it.

---

## Command line

Run without `-Gui` for scripting and automation. A few common commands:

```powershell
.\T2-PS-FIDO2-Manager.ps1                     # serial number, exit code 0/1
.\T2-PS-FIDO2-Manager.ps1 -Info               # CTAP2 getInfo
.\T2-PS-FIDO2-Manager.ps1 -Config             # vendor config bits (CCID)
.\T2-PS-FIDO2-Manager.ps1 -PinRetries         # PIN retry counter
.\T2-PS-FIDO2-Manager.ps1 -Pin                # set or change the PIN
.\T2-PS-FIDO2-Manager.ps1 -Pin -DryRun        # build the CBOR, send nothing
.\T2-PS-FIDO2-Manager.ps1 -CredsMeta          # storage statistics
.\T2-PS-FIDO2-Manager.ps1 -CredsList          # list resident credentials
.\T2-PS-FIDO2-Manager.ps1 -CredsDelete <hex>  # delete one credential
.\T2-PS-FIDO2-Manager.ps1 -Reset              # factory reset
```

Fingerprints (only on keys whose `getInfo` advertises `bioEnroll`):

```powershell
.\T2-PS-FIDO2-Manager.ps1 -BioList                          # sensor info + enrolments
.\T2-PS-FIDO2-Manager.ps1 -BioEnroll -BioName "Right index" # enrol; touch repeatedly
.\T2-PS-FIDO2-Manager.ps1 -BioRename <hex> -BioName "Name"
.\T2-PS-FIDO2-Manager.ps1 -BioDelete <hex>
```

Policy:

```powershell
.\T2-PS-FIDO2-Manager.ps1 -AlwaysUv on|off
.\T2-PS-FIDO2-Manager.ps1 -MinPinLength <n>    # one-way; lowering needs a reset
.\T2-PS-FIDO2-Manager.ps1 -ForcePinChange
```

Useful switches:

- `-Transport hid|ccid` — force a transport instead of `auto`.
- `-DryRun` — build and print the CBOR without sending it (where supported).
- `-Debug2` — trace the raw hex exchanged with the key.

Run the script with no arguments to see the serial; read the header comment block at the top of the script for the full, authoritative command reference.

---

## Troubleshooting

**"No hid device found"** — the key's HID interface wasn't opened. Confirm the session is elevated and the key is seated; run `.\T2-PS-FIDO2-Manager.ps1 -Info -Transport hid -Debug2` to see per-interface detail.

**`SW=6985` or `6D00` on a USB-CCID interface** — expected. The USB-CCID interface does not carry CTAP2; use `-Transport hid`, or an NFC reader.

**`CreateFile ... 0x5` (ACCESS_DENIED)** — not elevated. Re-run PowerShell as administrator.

**Enrolment seems stuck on "touch the sensor"** — the key is waiting for a fingerprint touch. Touch the sensor; lift and touch again for each sample. Use **Cancel** to abort — it stops the enrolment and discards the partial template from the key.

**Factory reset does nothing** — the key only accepts a reset within roughly 10 seconds of power-up. Unplug and replug it (or lift it off the NFC pad and place it back), then reset immediately.

---

## Security notes

- The tool performs standard FIDO2 / CTAP2 operations over Windows' own HID and PC/SC stacks. It does not bundle or depend on any external cryptographic library.
- A remembered PIN lives only in the running window's memory and is never persisted.
- Factory reset and credential deletion are irreversible. There is no undo.

---

## License and copyright

© Token2 Sàrl. All rights reserved.

 
