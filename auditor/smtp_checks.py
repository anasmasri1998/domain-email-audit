import smtplib
import socket
from config import SMTP_TIMEOUT


def check_starttls(mx_host: str, port: int = 25, timeout: int = SMTP_TIMEOUT):
    result = {
        "host": mx_host,
        "port": port,
        "connectable": False,
        "supports_starttls": False,
        "banner": None,
        "error": None,
    }

    try:
        server = smtplib.SMTP(mx_host, port, timeout=timeout)
        result["connectable"] = True

        server.ehlo()
        if server.has_extn("starttls"):
            result["supports_starttls"] = True

        result["banner"] = str(server.ehlo_resp) if server.ehlo_resp else None
        server.quit()

    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result