import time


class Flow:

    def __init__(self, key):

        self.key = key

        self.start_time = time.time()
        self.last_time = self.start_time

        self.forward_packets = 0
        self.backward_packets = 0

        self.forward_bytes = 0
        self.backward_bytes = 0

        self.forward_lengths = []
        self.backward_lengths = []

        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0

    # ---------------------------------------------------------
    # UPDATE FLOW
    # ---------------------------------------------------------

    def update(
        self,
        forward,
        packet_length,
        flags=None
    ):

        self.last_time = time.time()

        if forward:

            self.forward_packets += 1
            self.forward_bytes += packet_length
            self.forward_lengths.append(packet_length)

        else:

            self.backward_packets += 1
            self.backward_bytes += packet_length
            self.backward_lengths.append(packet_length)

        if flags:

            if "S" in flags:
                self.syn_count += 1

            if "A" in flags:
                self.ack_count += 1

            if "R" in flags:
                self.rst_count += 1

    # ---------------------------------------------------------
    # BASIC STATISTICS
    # ---------------------------------------------------------

    def duration(self):

        return max(
            self.last_time - self.start_time,
            0.000001
        )

    def total_packets(self):

        return (
            self.forward_packets
            + self.backward_packets
        )

    def total_bytes(self):

        return (
            self.forward_bytes
            + self.backward_bytes
        )

    # ---------------------------------------------------------
    # PACKET LENGTH MEANS
    # ---------------------------------------------------------

    def forward_length_mean(self):

        if not self.forward_lengths:
            return 0.0

        return sum(self.forward_lengths) / len(
            self.forward_lengths
        )

    def backward_length_mean(self):

        if not self.backward_lengths:
            return 0.0

        return sum(self.backward_lengths) / len(
            self.backward_lengths
        )

    # ---------------------------------------------------------
    # AVERAGE PACKET SIZE
    # ---------------------------------------------------------

    def average_packet_size(self):

        packets = self.total_packets()

        if packets == 0:
            return 0.0

        return self.total_bytes() / packets

    # ---------------------------------------------------------
    # FLOW BYTES / SECOND
    # ---------------------------------------------------------

    def flow_bytes_per_second(self):

        duration = self.duration()

        return self.total_bytes() / duration

    # ---------------------------------------------------------
    # FLOW PACKETS / SECOND
    # ---------------------------------------------------------

    def flow_packets_per_second(self):

        duration = self.duration()

        return self.total_packets() / duration

    # ---------------------------------------------------------
    # CICIDS FEATURE VECTOR
    # ---------------------------------------------------------

    def to_features(self):

        """
        Return features in EXACTLY the same order
        used during Random Forest training.
        """

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = self.key

        # CICIDS Flow Duration is in MICROSECONDS.
        duration_microseconds = self.duration() * 1_000_000

        features = {

            "Destination Port":
                dst_port,

            "Flow Duration":
                duration_microseconds,

            "Total Fwd Packets":
                self.forward_packets,

            "Total Backward Packets":
                self.backward_packets,

            "Total Length of Fwd Packets":
                self.forward_bytes,

            "Total Length of Bwd Packets":
                self.backward_bytes,

            "Flow Bytes/s":
                self.flow_bytes_per_second(),

            "Flow Packets/s":
                self.flow_packets_per_second(),

            "Fwd Packet Length Mean":
                self.forward_length_mean(),

            "Bwd Packet Length Mean":
                self.backward_length_mean(),

            "SYN Flag Count":
                self.syn_count,

            "ACK Flag Count":
                self.ack_count,

            "RST Flag Count":
                self.rst_count,

            "Average Packet Size":
                self.average_packet_size()
        }

        return features

    # ---------------------------------------------------------
    # DEBUG INFORMATION
    # ---------------------------------------------------------

    def summary(self):

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = self.key

        return {

            "source_ip": src_ip,

            "destination_ip": dst_ip,

            "source_port": src_port,

            "destination_port": dst_port,

            "protocol": protocol,

            "duration": self.duration(),

            "forward_packets":
                self.forward_packets,

            "backward_packets":
                self.backward_packets,

            "forward_bytes":
                self.forward_bytes,

            "backward_bytes":
                self.backward_bytes,

            "syn":
                self.syn_count,

            "ack":
                self.ack_count,

            "rst":
                self.rst_count
        }
