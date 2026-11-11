from pydantic import BaseModel, Field

from security_platform.models.location import SourceLocation


class ImportNode(BaseModel):
    module: str
    name: str | None = None
    alias: str | None = None
    location: SourceLocation


class ParameterNode(BaseModel):
    name: str
    type_annotation: str | None = None


class CallNode(BaseModel):
    caller_function: str | None
    callee_name: str
    location: SourceLocation


class FunctionNode(BaseModel):
    name: str
    is_async: bool = False
    parameters: list[ParameterNode] = Field(default_factory=list)
    decorators: list[str] = Field(default_factory=list)
    local_variables: set[str] = Field(default_factory=set)
    calls: list[CallNode] = Field(default_factory=list)
    location: SourceLocation
    has_return: bool = False
    has_yield: bool = False


class ClassNode(BaseModel):
    name: str
    base_classes: list[str] = Field(default_factory=list)
    methods: list[FunctionNode] = Field(default_factory=list)
    location: SourceLocation
