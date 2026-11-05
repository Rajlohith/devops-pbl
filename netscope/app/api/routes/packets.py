from fastapi import APIRouter

from app.schemas.packet import PacketFilter
from app.services.packet_service import filter_packets

router = APIRouter()


packets = [
    {
        "protocol": "TCP",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
    },
    {
        "protocol": "UDP",
        "source_ip": "192.168.1.15",
        "destination_ip": "192.168.1.30",
    },
    {
        "protocol": "TCP",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.30",
    },
    {
        "protocol": "ICMP",
        "source_ip": "192.168.1.20",
        "destination_ip": "192.168.1.10",
    },
]


@router.post("/packets/filter")
def filter_packet_endpoint(packet_filter: PacketFilter):

    filtered_packets = filter_packets(packets, packet_filter)

    return {
        "message": "Filter applied successfully",
        "filters": packet_filter,
        "packets": filtered_packets,
    }
