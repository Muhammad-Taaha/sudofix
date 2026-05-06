import sys
sys.path.insert(0, '.')  # make sure parser is importable

from parser.ast_nodes import CallNode
from parser.parser_factory import ParserFactory

def inspect_ast(source_code, language='python'):
    parser = ParserFactory.get_parser(language)
    if not parser:
        print(f"No parser for {language}")
        return
    tree = parser.parse(source_code)
    
    # Find the first CallNode in the tree
    call_nodes = []
    def collect_call_nodes(node):
        if isinstance(node, CallNode):
            call_nodes.append(node)
        # recurse
        for attr in dir(node):
            val = getattr(node, attr)
            if isinstance(val, list):
                for item in val:
                    if hasattr(item, '__dict__'):
                        collect_call_nodes(item)
            elif hasattr(val, '__dict__'):
                collect_call_nodes(val)
    collect_call_nodes(tree)
    
    if not call_nodes:
        print("No CallNode found")
        return
    
    # Examine each CallNode
    for i, cn in enumerate(call_nodes):
        print(f"\n=== CallNode {i+1} ===")
        print(f"Callee: {cn.callee}")
        print(f"Arguments: {len(cn.arguments)}")
        for j, arg in enumerate(cn.arguments):
            print(f"\n  Arg {j+1}:")
            print(f"    Type: {type(arg)}")
            print(f"    Class name: {arg.__class__.__name__}")
            print(f"    Attributes: {[a for a in dir(arg) if not a.startswith('_')]}")
            # Try to get value/name if present
            if hasattr(arg, 'value'):
                print(f"    value: {arg.value}")
            if hasattr(arg, 'name'):
                print(f"    name: {arg.name}")
            if hasattr(arg, 'type'):
                print(f"    type: {arg.type}")
            # For UnifiedNode, maybe there is a node_type attribute
            if hasattr(arg, 'node_type'):
                print(f"    node_type: {arg.node_type}")
            # Check if it's a list-like
            if hasattr(arg, 'elements'):
                print(f"    elements: {arg.elements}")
            # Show a few lines of code snippet (if available)
            if hasattr(arg, 'code'):
                print(f"    code: {arg.code[:100]}")

if __name__ == "__main__":
    # Test with a safe command injection call (literal)
    safe_code = "os.system('ls -la')"
    print("=== SAFE CODE ===")
    inspect_ast(safe_code, 'python')
    
    # Test with a vulnerable call (variable)
    vuln_code = "os.system(user_input)"
    print("\n=== VULNERABLE CODE ===")
    inspect_ast(vuln_code, 'python')