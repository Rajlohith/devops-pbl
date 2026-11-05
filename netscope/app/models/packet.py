from datetime import datetime
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)


_RECOGNIZED_TRANSPORT_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    132: "SCTP",
}
_MAC_ADDRESS_PATTERN = re.compile(
    r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
)


class TransportProtocol(BaseModel):
    number: int | None = Field(default=None, ge=0, le=255)
    name: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("name must not be empty")
        return value

    @model_validator(mode="after")
    def validate_protocol_identity(self) -> "TransportProtocol":
        if self.number is None and self.name is None:
            raise ValueError("number or name must be provided")

        if self.number is not None and self.name is not None:
            recognized_name = _RECOGNIZED_TRANSPORT_PROTOCOLS.get(self.number)
            if recognized_name is not None and recognized_name.casefold() != self.name.casefold():
                raise ValueError("number and name identify different protocols")

            recognized_number = next(
                (
                    number
                    for number, name in _RECOGNIZED_TRANSPORT_PROTOCOLS.items()
                    if name.casefold() == self.name.casefold()
                ),
                None,
            )
            if recognized_number is not None and recognized_number != self.number:
                raise ValueError("number and name identify different protocols")

        return self


class Packet(BaseModel):
    capture_id: UUID
    packet_number: int = Field(gt=0)
    timestamp: datetime
    captured_length: int = Field(ge=0)
    original_length: int = Field(ge=0)

    source_mac: str | None = None
    destination_mac: str | None = None
    ether_type: int | None = Field(default=None, ge=0, le=65535)
    vlan_id: int | None = Field(default=None, ge=0, le=4094)

    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    ip_version: Literal[4, 6] | None = None
    ttl_or_hop_limit: int | None = Field(default=None, ge=0, le=255)
    transport_protocol: TransportProtocol | None = None

    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    tcp_flags: str | None = None
    tcp_sequence_number: int | None = Field(default=None, ge=0)
    tcp_acknowledgement_number: int | None = Field(default=None, ge=0)
    udp_length: int | None = Field(default=None, ge=0)

    application_protocol: str | None = None
    application_metadata: dict[str, Any] | None = None

    @field_validator("source_mac", "destination_mac")
    @classmethod
    def validate_mac_address(cls, value: str | None) -> str | None:
        if value is not None and not _MAC_ADDRESS_PATTERN.fullmatch(value):
            raise ValueError("MAC address must contain six hexadecimal octets")
        return value

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_packet_fields(self) -> "Packet":
        if self.captured_length > self.original_length:
            raise ValueError("captured_length must not exceed original_length")

        if self.ip_version is not None:
            for address in (self.source_ip, self.destination_ip):
                if address is not None and address.version != self.ip_version:
                    raise ValueError(
                        "ip_version must match the version of provided IP addresses"
                    )

        return self
