import sys
from pathlib import Path
from parser.parser_factory import ParserFactory

def inspect_ast(file_path, max_depth=3, max_nodes=30):
    file_path = Path(file_path)
    parser = ParserFactory.get_parser(str(file_path))
    if not parser:
        print(f"No parser for {file_path.suffix}")
        return

    print(f"\n📄 Parsing: {file_path}")
    nodes = parser.parse(str(file_path))
    print(f"Total nodes: {len(nodes)}")

    for i, node in enumerate(nodes[:max_nodes]):
        print(f"\n--- Node {i+1} ---")
        print(f"  Type : {node.node_type}")
        print(f"  Name : {node.name}")
        print(f"  Lines: {node.start_line} - {node.end_line}")
        print(f"  Lang : {node.language}")
        code_preview = node.code[:200].replace('\n', ' ').strip()
        print(f"  Code : {code_preview}{'...' if len(node.code) > 200 else ''}")
        print(f"  Code length : {len(node.code)} bytes")

        # Additional fields for specific node types (if present)
        if hasattr(node, "callee"):
            print(f"  Callee: {node.callee}")
        if hasattr(node, "arguments"):
            print(f"  Args: {node.arguments}")
        if hasattr(node, "condition"):
            print(f"  Condition: {node.condition}")
        if hasattr(node, "value"):
            print(f"  Value: {node.value}")

        # If the node has children (some parsers might have this attribute)
        if hasattr(node, "children") and node.children:
            print(f"  Children: {len(node.children)}")
        elif hasattr(node, "body") and node.body:
            print(f"  Body length: {len(node.body)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python inspect_ast.py <file>")
        sys.exit(1)
    inspect_ast(sys.argv[1])