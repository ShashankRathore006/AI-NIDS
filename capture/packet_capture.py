from scapy.all import sniff, IP, TCP, UDP


INTERFACE = "wlan0"


def process_packet(packet):

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst

    protocol = "OTHER"
    sport = "-"
    dport = "-"
    flags = "-"

    if TCP in packet:

        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = str(packet[TCP].flags)

    elif UDP in packet:

        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    print(
        f"{src}:{sport} -> "
        f"{dst}:{dport} | "
        f"{protocol} | "
        f"size={len(packet)} | "
        f"flags={flags}"
    )


print("=" * 70)
print("NIDS LIVE PACKET CAPTURE")
print("=" * 70)

print(f"Interface: {INTERFACE}")
print("Listening for packets...")
print("Press CTRL+C to stop.\n")


sniff(
    iface=INTERFACE,
    prn=process_packet,
    store=False
)
