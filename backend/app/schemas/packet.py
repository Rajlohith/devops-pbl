from pydantic import BaseModel


class PacketFilter(BaseModel):
    protocol: str | None = None
    source_ip: str | None = None
