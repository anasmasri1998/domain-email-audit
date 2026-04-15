import socket
import ssl
from datetime import datetime

def check_tls_certificate(host: str, port: int = 25, timeout: int = 8):
    result = {
        "host": host,
        "port": port,
        "tls_supported": False,
        "cert_subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["tls_supported"] = True
                result["cert_subject"] = cert.get("subject")
                result["issuer"] = cert.get("issuer")
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
    except Exception as e:
        result["error"] = str(e)

    return result