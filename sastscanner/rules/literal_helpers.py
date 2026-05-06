import re

# Set to True to enable debugging
DEBUG = True

def is_constant_literal(arg, depth=0, prefix=""):
    indent = "  " * depth
    if DEBUG:
        print(f"{prefix}{indent}Checking: {repr(arg)} type={type(arg).__name__}")

    # Primitive types
    if isinstance(arg, (int, float, bool)):
        if DEBUG:
            print(f"{prefix}{indent}-> primitive -> True")
        return True

    # String
    if isinstance(arg, str):
        # Quoted literal
        if (arg.startswith("'") and arg.endswith("'")) or (arg.startswith('"') and arg.endswith('"')):
            if DEBUG:
                print(f"{prefix}{indent}-> quoted string -> True")
            return True
        # List literal representation
        if arg.startswith('[') and arg.endswith(']'):
            if DEBUG:
                print(f"{prefix}{indent}-> list string -> checking elements")
            inner = arg[1:-1].strip()
            if not inner:
                if DEBUG:
                    print(f"{prefix}{indent}   empty list -> True")
                return True
            parts = re.split(r',\s*', inner)
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if part[0] in "\"'" and part[-1] in "\"'":
                    continue
                if part.isdigit() or (part[0] == '-' and part[1:].isdigit()):
                    continue
                if part.startswith('[') and part.endswith(']'):
                    if not is_constant_literal(part, depth+1, prefix):
                        if DEBUG:
                            print(f"{prefix}{indent}   nested list not literal -> False")
                        return False
                    continue
                if DEBUG:
                    print(f"{prefix}{indent}   non-literal token: {part} -> False")
                return False
            if DEBUG:
                print(f"{prefix}{indent}-> list literal -> True")
            return True
        # Unquoted -> variable
        if DEBUG:
            print(f"{prefix}{indent}-> unquoted string (likely variable) -> False")
        return False

    # List of nodes
    if isinstance(arg, list):
        if DEBUG:
            print(f"{prefix}{indent}-> list of {len(arg)} items -> checking each")
        result = all(is_constant_literal(item, depth+1, prefix) for item in arg)
        if DEBUG:
            print(f"{prefix}{indent}-> result = {result}")
        return result

    # AST node handling
    # Check for binary operation (unsafe)
    if hasattr(arg, 'op') or (hasattr(arg, 'node_type') and arg.node_type == 'binary_op'):
        if DEBUG:
            print(f"{prefix}{indent}-> binary operation -> False")
        return False

    # Value recursion
    if hasattr(arg, 'value'):
        if DEBUG:
            print(f"{prefix}{indent}-> has .value, recursing")
        return is_constant_literal(arg.value, depth+1, prefix)

    # Node type literal
    if hasattr(arg, 'node_type'):
        if arg.node_type in ('string', 'number', 'boolean', 'literal', 'list'):
            if DEBUG:
                print(f"{prefix}{indent}-> node_type={arg.node_type} -> True")
            return True

    # Some parsers use 'type'
    if hasattr(arg, 'type'):
        if arg.type in ('str', 'int', 'float', 'bool', 'list', 'constant'):
            if DEBUG:
                print(f"{prefix}{indent}-> type={arg.type} -> True")
            return True

    # Variable name
    if hasattr(arg, 'name') and arg.name:
        if DEBUG:
            print(f"{prefix}{indent}-> has name '{arg.name}' -> False (variable)")
        return False

    # Recurse into children/elements
    if hasattr(arg, 'children') and arg.children:
        if DEBUG:
            print(f"{prefix}{indent}-> has children, checking all")
        return all(is_constant_literal(child, depth+1, prefix) for child in arg.children)
    if hasattr(arg, 'elements') and arg.elements:
        if DEBUG:
            print(f"{prefix}{indent}-> has elements, checking all")
        return all(is_constant_literal(elem, depth+1, prefix) for elem in arg.elements)

    # Default unsafe
    if DEBUG:
        print(f"{prefix}{indent}-> default -> False")
    return False