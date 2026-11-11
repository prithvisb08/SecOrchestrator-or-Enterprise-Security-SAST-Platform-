
from pydantic import BaseModel

from security_platform.models.location import SourceLocation
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class TaintSource(BaseModel):
    name: str
    description: str


class TaintSink(BaseModel):
    name: str
    description: str
    vulnerability_type: VulnerabilityType | str


class Sanitizer(BaseModel):
    name: str
    description: str


class DataFlowNode(BaseModel):
    node_type: str  # "SOURCE", "PROPAGATION", "SANITIZER", "SINK"
    expression: str
    location: SourceLocation


class TaintPath(BaseModel):
    source: DataFlowNode
    propagations: list[DataFlowNode]
    sink: DataFlowNode
    is_sanitized: bool = False
