from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class SourceDefinition(BaseModel):
    name: str
    type: str  # "attribute", "call", "subscript"
    description: str


class SinkDefinition(BaseModel):
    vulnerability_type: VulnerabilityType
    patterns: list[str]


class SanitizerDefinition(BaseModel):
    name: str
    description: str
    valid_sinks: list[VulnerabilityType] = Field(default_factory=list)


class RulePack(BaseModel):
    version: str
    sources: list[SourceDefinition] = Field(default_factory=list)
    sinks: dict[str, SinkDefinition] = Field(default_factory=dict)
    sanitizers: dict[str, SanitizerDefinition] = Field(default_factory=dict)


@lru_cache(maxsize=1)
def load_default_rule_pack() -> RulePack:
    yaml_path = Path(__file__).parent / "sources_sinks.yaml"
    if not yaml_path.exists():
        return RulePack(version="1.0.0")

    raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    version = str(raw.get("version", "1.0.0"))

    # Load sources from all frameworks
    all_sources: list[SourceDefinition] = []
    for framework, data in raw.get("frameworks", {}).items():
        for src in data.get("sources", []):
            all_sources.append(SourceDefinition(
                name=src["name"],
                type=src.get("type", "call"),
                description=src.get("description", f"Source from {framework}")
            ))

    # Load sinks
    all_sinks: dict[str, SinkDefinition] = {}
    for sink_key, data in raw.get("sinks", {}).items():
        v_type_str = data.get("vulnerability_type", "VULNERABILITY")
        try:
            v_type = VulnerabilityType(v_type_str)
        except ValueError:
            v_type = VulnerabilityType.COMMAND_INJECTION
        all_sinks[sink_key] = SinkDefinition(
            vulnerability_type=v_type,
            patterns=data.get("patterns", [])
        )

    # Load sanitizers
    all_sanitizers: dict[str, SanitizerDefinition] = {}
    for item in raw.get("sanitizers", []):
        s_name = item["name"]
        valid_sinks: list[VulnerabilityType] = []
        for s_type in item.get("valid_sinks", []):
            try:
                valid_sinks.append(VulnerabilityType(s_type))
            except ValueError:
                pass
        all_sanitizers[s_name] = SanitizerDefinition(
            name=s_name,
            description=item.get("description", ""),
            valid_sinks=valid_sinks
        )

    return RulePack(
        version=version,
        sources=all_sources,
        sinks=all_sinks,
        sanitizers=all_sanitizers
    )
