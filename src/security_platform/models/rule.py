from pydantic import BaseModel, Field

from security_platform.enums.severity import Severity
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class Rule(BaseModel):
    rule_id: str
    name: str
    category: Category
    vulnerability_type: VulnerabilityType
    description: str
    default_severity: Severity
    enabled: bool = True
    references: list[str] = Field(default_factory=list)
