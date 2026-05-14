from sastscanner.taint.taint_engine import TaintEngine
from parser.ast_nodes import AssignNode, CallNode


def run_test():
    nodes = [
        # x = input()
        AssignNode(
            name=None,
            code="x = input()",
            file_path="test.py",
            start_line=1,
            end_line=1,
            language="python",
            targets=["x"],
            value="input()",
        ),
        # y = x
        AssignNode(
            name=None,
            code="y = x",
            file_path="test.py",
            start_line=2,
            end_line=2,
            language="python",
            targets=["y"],
            value="x",
        ),
        # os.system(y)
        CallNode(
            name=None,
            code="os.system(y)",
            file_path="test.py",
            start_line=3,
            end_line=3,
            language="python",
            callee="os.system",
            arguments=["y"],
        ),
    ]

    engine = TaintEngine(language="python")
    issues = engine.analyze(nodes)

    print("\n🔥 ISSUES FOUND:")
    for i in issues:
        print(i)


if __name__ == "__main__":
    run_test()
