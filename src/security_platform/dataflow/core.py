from pydantic import BaseModel, Field

from security_platform.models.location import SourceLocation
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class TaintSource(BaseModel):
    name: str
    description: str


class TaintSink(BaseModel):
    name: str
    description: str
    vulnerability_type: VulnerabilityType | str
    patterns: list[str] = Field(default_factory=list)


class Sanitizer(BaseModel):
    name: str
    description: str
    valid_sinks: list[VulnerabilityType] = Field(default_factory=list)


class DataFlowNode(BaseModel):
    node_type: str  # "SOURCE", "PROPAGATION", "SANITIZER", "SINK"
    expression: str
    location: SourceLocation
    sanitizers: list[str] = Field(default_factory=list)


class TaintPath(BaseModel):
    source: DataFlowNode
    propagations: list[DataFlowNode] = Field(default_factory=list)
    sink: DataFlowNode
    is_sanitized: bool = False
    sanitizer_name: str | None = None
