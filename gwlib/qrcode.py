"""Generate local SVG QR codes without sending connection credentials to a third party."""
import subprocess


def svg(value):
    if not value or len(value.encode())>2953:
        return None
    try:
        result=subprocess.run(
            ['qrencode','-t','SVG','-o','-','-s','6'],
            input=value.encode(),capture_output=True,check=True,timeout=5,
        )
    except (OSError,subprocess.SubprocessError):
        return None
    if len(result.stdout)>512*1024:
        return None
    return result.stdout.decode()
