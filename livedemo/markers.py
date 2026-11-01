"""ATHENA decisions as real packets. Every event is sent as a small UDP datagram to 127.0.0.1:47474. Wireshark captures the loopback adapter next to the Wi-Fi adapter, so
ONE capture shows the attack packets, the decisions and the effect, in time order, on the same clock. They stay on this laptop: nothing is ever sent to the attacker."""
import socket

PORT = 47474
_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def emit(stage: str, **kw) -> str:
    text = "ATHENA " + stage + " " + " ".join(f"{k}={v}" for k, v in kw.items())
    try:
        _s.sendto(text.encode(), ("127.0.0.1", PORT))
    except OSError:
        pass
    return text
