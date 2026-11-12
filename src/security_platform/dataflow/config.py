from security_platform.dataflow.core import Sanitizer, TaintSink, TaintSource
from security_platform.rules.loader import load_default_rule_pack
from security_platform.taxonomy.vulnerability_types import VulnerabilityType

_rule_pack = load_default_rule_pack()

DEFAULT_SOURCES: dict[str, TaintSource] = {
    src.name: TaintSource(name=src.name, description=src.description)
    for src in _rule_pack.sources
}

# Add standard built-ins if not already in YAML
if "sys.argv" not in DEFAULT_SOURCES:
    DEFAULT_SOURCES["sys.argv"] = TaintSource(name="sys.argv", description="Command-line argument")
if "os.environ.get" not in DEFAULT_SOURCES:
    DEFAULT_SOURCES["os.environ.get"] = TaintSource(name="os.environ.get", description="Environment variable")

DEFAULT_SINKS: dict[str, TaintSink] = {}
for _sink_name, sink_def in _rule_pack.sinks.items():
    for pattern in sink_def.patterns:
        DEFAULT_SINKS[pattern] = TaintSink(
            name=pattern,
            description=f"Sink for {sink_def.vulnerability_type}",
            vulnerability_type=sink_def.vulnerability_type,
            patterns=sink_def.patterns
        )

# Fallback defaults
if "sqlite3.execute" not in DEFAULT_SINKS:
    DEFAULT_SINKS["sqlite3.execute"] = TaintSink(
        name="sqlite3.execute", description="SQL Execution", vulnerability_type=VulnerabilityType.SQL_INJECTION
    )
if "cursor.execute" not in DEFAULT_SINKS:
    DEFAULT_SINKS["cursor.execute"] = TaintSink(
        name="cursor.execute", description="SQL Execution", vulnerability_type=VulnerabilityType.SQL_INJECTION
    )
if "os.system" not in DEFAULT_SINKS:
    DEFAULT_SINKS["os.system"] = TaintSink(
        name="os.system", description="Shell Command", vulnerability_type=VulnerabilityType.COMMAND_INJECTION
    )

DEFAULT_SANITIZERS: dict[str, Sanitizer] = {
    san.name: Sanitizer(
        name=san.name,
        description=san.description,
        valid_sinks=san.valid_sinks
    )
    for san in _rule_pack.sanitizers.values()
}


def match_sink(callee_name: str) -> TaintSink | None:
    """Matches a callee expression against registered sinks, including wildcard patterns."""
    if callee_name in DEFAULT_SINKS:
        return DEFAULT_SINKS[callee_name]

    # Wildcard match (e.g. *.execute matches db.cursor().execute)
    for pattern, sink in DEFAULT_SINKS.items():
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g. ".execute"
            if callee_name.endswith(suffix):
                return sink

    # Check method name directly for known critical operations
    method = callee_name.split(".")[-1]
    if method == "execute" or method == "executemany":
        return TaintSink(
            name=callee_name,
            description="SQL Execution",
            vulnerability_type=VulnerabilityType.SQL_INJECTION
        )

    return None


def is_sanitizer_valid_for_sink(sanitizer_name: str, sink_vuln_type: VulnerabilityType | str) -> bool:
    """Returns True if the given sanitizer is safe for the specified vulnerability type."""
    san = DEFAULT_SANITIZERS.get(sanitizer_name)
    if not san:
        # Unknown sanitizer is not trusted to sanitize by default
        return False
    vuln_enum = (
        sink_vuln_type
        if isinstance(sink_vuln_type, VulnerabilityType)
        else VulnerabilityType(sink_vuln_type)
    )
    return vuln_enum in san.valid_sinks
