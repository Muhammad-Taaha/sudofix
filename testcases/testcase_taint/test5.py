from sastscanner.taint.taint_engine import TaintEngine
from parser.ast_nodes import UnifiedNode, AssignNode, ReturnNode, CallNode

def run_test():
    nodes = [
        # def get_input():
        UnifiedNode(
            node_type="function",
            name="get_input",
            code="def get_input():\n    return input()",
            file_path="test.py",
            start_line=1,
            end_line=2,
            language="python",
        ),
        # return input()
        ReturnNode(
            name=None,
            code="return input()",
            file_path="test.py",
            start_line=2,
            end_line=2,
            language="python",
            value="input()",
        ),
        # x = get_input()
        AssignNode(
            name=None,
            code="x = get_input()",
            file_path="test.py",
            start_line=4,
            end_line=4,
            language="python",
            targets=["x"],
            value="get_input()",
        ),
        # os.system(x)
        CallNode(
            name=None,
            code="os.system(x)",
            file_path="test.py",
            start_line=5,
            end_line=5,
            language="python",
            callee="os.system",
            arguments=["x"],
        ),
    ]

    engine = TaintEngine(language="python")
    issues = engine.analyze(nodes)

    print("\n🔥 ISSUES:")
    for i in issues:
        print(i)

if __name__ == "__main__":
    run_test()
