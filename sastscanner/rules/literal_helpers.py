import re

# Set to True to enable debugging
DEBUG = True


def is_constant_literal(arg, depth=0, prefix=""):
    indent = "  " * depth

    if DEBUG:
        print(f"{prefix}{indent}Checking: {
              repr(arg)} type={type(arg).__name__}")

    # ---------------------------------------------------
    # Primitive types
    # ---------------------------------------------------
    if isinstance(arg, (int, float, bool)):
        if DEBUG:
            print(f"{prefix}{indent}-> primitive -> True")
        return True

    # ---------------------------------------------------
    # String handling
    # ---------------------------------------------------
    if isinstance(arg, str):

        value = arg.strip()

        # ---------------------------------------------------
        # Enum/constants like ldap.SCOPE_SUBTREE
        # ---------------------------------------------------
        if "." in value:
            last = value.split(".")[-1]

            if last.isupper():
                if DEBUG:
                    print(f"{prefix}{indent}-> enum/constant detected -> True")
                return True

        # ---------------------------------------------------
        # List literal representation
        # Example: ['a', 'b']
        # ---------------------------------------------------
        if value.startswith("[") and value.endswith("]"):

            if DEBUG:
                print(f"{prefix}{indent}-> list string -> checking elements")

            inner = value[1:-1].strip()

            if not inner:
                if DEBUG:
                    print(f"{prefix}{indent}   empty list -> True")
                return True

            parts = re.split(r',\s*', inner)

            for part in parts:

                part = part.strip()

                if not part:
                    continue

                # String literal item
                if (
                    (part.startswith("'") and part.endswith("'")) or
                    (part.startswith('"') and part.endswith('"'))
                ):
                    continue

                # Numeric item
                if part.isdigit() or (
                    part.startswith("-") and part[1:].isdigit()
                ):
                    continue

                # Nested list
                if part.startswith("[") and part.endswith("]"):

                    if not is_constant_literal(
                        part,
                        depth + 1,
                        prefix
                    ):

                        if DEBUG:
                            print(
                                f"{prefix}{indent}"
                                f"   nested list not literal -> False"
                            )

                        return False

                    continue

                # Variable/non-literal
                if DEBUG:
                    print(
                        f"{prefix}{indent}"
                        f"   non-literal token: {part} -> False"
                    )

                return False

            if DEBUG:
                print(f"{prefix}{indent}-> list literal -> True")

            return True

        # ---------------------------------------------------
        # f-string handling
        # ---------------------------------------------------
        if value.startswith(("f'", 'f"', "F'", 'F"')):

            if DEBUG:
                print(f"{prefix}{indent}-> f-string detected -> True")

            return True

        # ---------------------------------------------------
        # Quoted string literal
        # ---------------------------------------------------
        if (
            (value.startswith("'") and value.endswith("'")) or
            (value.startswith('"') and value.endswith('"'))
        ):

            # ---------------------------------------------------
            # Dangerous string concatenation
            # ---------------------------------------------------
            if "+" in value:

                if DEBUG:
                    print(
                        f"{prefix}{indent}"
                        f"-> string concatenation detected -> False"
                    )

                return False

            # ---------------------------------------------------
            # Dangerous .format()
            # ---------------------------------------------------
            if ".format(" in value:

                if DEBUG:
                    print(
                        f"{prefix}{indent}"
                        f"-> .format() detected -> False"
                    )

                return False

            # ---------------------------------------------------
            # Safe quoted literal
            # ---------------------------------------------------
            if DEBUG:
                print(
                    f"{prefix}{indent}"
                    f"-> quoted string literal -> True"
                )

            return True

        # ---------------------------------------------------
        # Unquoted variable/string
        # ---------------------------------------------------
        if DEBUG:
            print(
                f"{prefix}{indent}"
                f"-> unquoted string (likely variable) -> False"
            )

        return False

    # ---------------------------------------------------
    # Python list object
    # ---------------------------------------------------
    if isinstance(arg, list):

        if DEBUG:
            print(
                f"{prefix}{indent}"
                f"-> list of {len(arg)} items -> checking each"
            )

        result = all(
            is_constant_literal(item, depth + 1, prefix)
            for item in arg
        )

        if DEBUG:
            print(f"{prefix}{indent}-> result = {result}")

        return result

    # ---------------------------------------------------
    # Binary operation detection
    # ---------------------------------------------------
    if hasattr(arg, 'op'):

        if DEBUG:
            print(f"{prefix}{indent}-> binary operation -> False")

        return False

    if hasattr(arg, 'node_type'):

        if arg.node_type == 'binary_op':

            if DEBUG:
                print(f"{prefix}{indent}-> binary_op node -> False")

            return False

    # ---------------------------------------------------
    # Value recursion
    # ---------------------------------------------------
    if hasattr(arg, 'value'):

        if DEBUG:
            print(f"{prefix}{indent}-> has .value, recursing")

        return is_constant_literal(
            arg.value,
            depth + 1,
            prefix
        )

    # ---------------------------------------------------
    # AST node type handling
    # ---------------------------------------------------
    if hasattr(arg, 'node_type'):

        if arg.node_type in (
            'number',
            'boolean',
            'literal'
        ):

            if DEBUG:
                print(
                    f"{prefix}{indent}"
                    f"-> node_type={arg.node_type} -> True"
                )

            return True

        if arg.node_type == 'string':

            if hasattr(arg, 'value'):

                return is_constant_literal(
                    arg.value,
                    depth + 1,
                    prefix
                )

    # ---------------------------------------------------
    # Alternative parser type attribute
    # ---------------------------------------------------
    if hasattr(arg, 'type'):

        if arg.type in (
            'int',
            'float',
            'bool',
            'constant'
        ):

            if DEBUG:
                print(
                    f"{prefix}{indent}"
                    f"-> type={arg.type} -> True"
                )

            return True

        if arg.type == 'str':

            if hasattr(arg, 'value'):

                return is_constant_literal(
                    arg.value,
                    depth + 1,
                    prefix
                )

    # ---------------------------------------------------
    # Variable detection
    # ---------------------------------------------------
    if hasattr(arg, 'name') and arg.name:

        if DEBUG:
            print(
                f"{prefix}{indent}"
                f"-> has name '{arg.name}' -> False"
            )

        return False

    # ---------------------------------------------------
    # Recursive child traversal
    # ---------------------------------------------------
    if hasattr(arg, 'children') and arg.children:

        if DEBUG:
            print(
                f"{prefix}{indent}"
                f"-> has children, checking all"
            )

        return all(
            is_constant_literal(
                child,
                depth + 1,
                prefix
            )
            for child in arg.children
        )

    if hasattr(arg, 'elements') and arg.elements:

        if DEBUG:
            print(
                f"{prefix}{indent}"
                f"-> has elements, checking all"
            )

        return all(
            is_constant_literal(
                elem,
                depth + 1,
                prefix
            )
            for elem in arg.elements
        )

    # ---------------------------------------------------
    # Default unsafe
    # ---------------------------------------------------
    if DEBUG:
        print(f"{prefix}{indent}-> default -> False")

    return False
