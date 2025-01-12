from pydantic import BaseModel

class DNSRecord(BaseModel):
    type: str
    host: str
    value: str
    ttl: int
    
class DomainAuthResponse(BaseModel):
    message: str
    dns_records: list[DNSRecord]
    domain_id: str

class DomainAuthRequest(BaseModel):
    domain: str
    subdomain: str = "email"  # Default value
    custom_spf: bool = True   # Default value

