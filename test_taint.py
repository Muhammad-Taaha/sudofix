import sys
from pathlib import Path
from parser.parser_factory import ParserFactory
from sastscanner.taint.taint_engine import TaintEngine

def test_taint(file_path):
    parser = ParserFactory.get_parser(file_path)
    if not parser:
        print("No parser for", file_path)
        return
    nodes = parser.parse(file_path)
    if not nodes:
        print("No nodes")
        return
    print(f"Parsed {len(nodes)} nodes")
    language = getattr(nodes[0], 'language', 'unknown')
    engine = TaintEngine()
    findings = engine.analyze(nodes, language=language)
    print(f"Taint findings: {len(findings)}")
    for f in findings[:5]:
        print("  -", f)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_taint.py <file>")
        sys.exit(1)
    test_taint(sys.argv[1])
