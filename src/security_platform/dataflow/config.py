from security_platform.dataflow.core import Sanitizer, TaintSink, TaintSource
from security_platform.taxonomy.vulnerability_types import VulnerabilityType

DEFAULT_SOURCES = {
    "request.GET.get": TaintSource(name="request.GET.get", description="HTTP GET parameter"),
    "request.POST.get": TaintSource(name="request.POST.get", description="HTTP POST parameter"),
    "os.environ.get": TaintSource(name="os.environ.get", description="Environment variable"),
    "sys.argv": TaintSource(name="sys.argv", description="Command-line argument")
}

DEFAULT_SINKS = {
    "sqlite3.execute": TaintSink(name="sqlite3.execute", description="SQL Execution", vulnerability_type=VulnerabilityType.SQL_INJECTION),
    "cursor.execute": TaintSink(name="cursor.execute", description="SQL Execution", vulnerability_type=VulnerabilityType.SQL_INJECTION),
    "subprocess.Popen": TaintSink(name="subprocess.Popen", description="Subprocess Execution", vulnerability_type=VulnerabilityType.COMMAND_INJECTION),
    "os.system": TaintSink(name="os.system", description="Shell Command", vulnerability_type=VulnerabilityType.COMMAND_INJECTION),
    "eval": TaintSink(name="eval", description="Dynamic Code Execution", vulnerability_type=VulnerabilityType.CODE_INJECTION)
}

DEFAULT_SANITIZERS = {
    "shlex.quote": Sanitizer(name="shlex.quote", description="Shell escaping"),
    "bleach.clean": Sanitizer(name="bleach.clean", description="HTML sanitization"),
    "int": Sanitizer(name="int", description="Integer casting (safe from injection)")
}
