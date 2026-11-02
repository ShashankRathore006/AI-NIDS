from flow import Flow


key = (
    "192.168.1.8",
    "8.8.8.8",
    50000,
    443,
    "TCP"
)

flow = Flow(key)


# Simulate forward packets
flow.update(
    forward=True,
    packet_length=100,
    flags="S"
)

flow.update(
    forward=True,
    packet_length=200,
    flags="A"
)

# Simulate backward packet
flow.update(
    forward=False,
    packet_length=300,
    flags="SA"
)

flow.update(
    forward=True,
    packet_length=150,
    flags="A"
)


features = flow.to_features()


print("=" * 70)
print("FLOW FEATURE TEST")
print("=" * 70)

for name, value in features.items():

    print(
        f"{name:35} : {value}"
    )

print("=" * 70)

print(f"Total features: {len(features)}")
