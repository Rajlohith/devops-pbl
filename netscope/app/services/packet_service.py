def filter_packets(packets, packet_filter):
    filtered_packets = []

    for packet in packets:
        if (
            packet_filter.protocol is not None
            and packet["protocol"] != packet_filter.protocol
        ):
            continue

        if (
            packet_filter.source_ip is not None
            and packet["source_ip"] != packet_filter.source_ip
        ):
            continue

        filtered_packets.append(packet)

    return filtered_packets
