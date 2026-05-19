## in this file we are going to detect the places where the user opens the file without having 
from typing import List , Dict , Any 
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode
from ..literal_helpers import is_constant_literal

class PathTraversalOpenRule(BaseRule):
    @property 
    def name(self)->str:
        return "Path Traversal via open()"
    @property 
    def severity(self)->str:
        return "High"
    @property 
    def cwe_id(self)-> str:
        return "CWE-22"
    SINKS = {
        "python": ["open", "file", "io.open", "pathlib.Path.read_text", "pathlib.Path.write_text"],
        "javascript": ["fs.readFileSync", "fs.readFile", "fs.writeFileSync", "fs.writeFile", "fs.createReadStream", "fs.createWriteStream"],
        "java": ["FileInputStream", "FileOutputStream", "RandomAccessFile", "Files.readAllBytes", "Files.write"],
        "go": ["os.Open", "os.Create", "ioutil.ReadFile", "ioutil.WriteFile", "os.OpenFile"],
        "c": ["fopen", "open", "fread", "fwrite"],
        "cpp": ["fopen", "open", "ifstream", "ofstream", "fstream"],
        "rust": ["std::fs::File::open", "std::fs::read", "std::fs::write", "std::fs::create_dir_all"],
    }
    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]):
        lang = self._get_language(chunk)
        if lang not in self.SINKS:
            return f"the languague is not supported => {lang}"
        try :
            nodes = chunk.get("nodes",[])
        except :
            raise "not able to find the node structure"
        findings=[]
        for node in nodes :
            if not isinstance(node,CallNode):
                continue 
            callee = node.callee
            # checking if the  call matches any value in the sink 
            is_sink = any(callee == sink or callee.startswith(sink + ".") for sink in self.SINKS[lang])
            if not is_sink :
                continue 
            args = getattr(node, "arguments", [])
            if args:
                path_arg = args[0]
                taint_vars = context.get("taint_vars")
                if taint_vars:
                    import re
                    is_tainted = False
                    for var in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", str(path_arg)):
                        if taint_vars.is_tainted(var):
                            is_tainted = True
                            break
                    if is_tainted:
                        findings.append(self._create_finding(chunk, node, callee, path_arg))
                elif not is_constant_literal(path_arg):
                    findings.append(self._create_finding(chunk, node, callee, path_arg))
            else:
                # No arguments? Still potentially dangerous
                findings.append(self._create_finding(chunk, node, callee, "unknown"))
        return findings
    def _create_finding(self, chunk, node, callee, path_arg):
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            file_path=chunk.get("file_path", ""),
            line_start=node.start_line,
            line_end=node.end_line,
            message=f"Potential path traversal via `{callee}` with user-controlled path: {path_arg[:100]}",
            code_snippet=node.code,
            cwe_id=self.cwe_id,
        )
            


