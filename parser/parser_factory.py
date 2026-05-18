from typing import Dict, Optional
from pathlib import Path
from .base_parser import BaseParser
from .python_parser import PythonParser
from .java_parser import JavaParser
from .javascript_parser import JavaScriptParser
from .c_parser import CParser
from .cpp_parser import CppParser
from .go_parser import GoParser
from .rust_parser import RustParser


# ==============================
# DEBUG WRAPPER (FIXED)
# ==============================
class DebugParser:
    def __init__(self, parser):
        self.parser = parser

    def parse(self, file_path):
        print(f"\n🧪 [PARSER DEBUG] {file_path}")

        try:
            result = self.parser.parse(file_path)
        except Exception as e:
            print(f"❌ Parser crashed: {e}")
            return []

        if result is None:
            print("❌ Parser returned None")
            return []

        print(f"🧪 [PARSER RESULT] type={type(result)} | length={len(result)}")
        print(f"🧪 [PARSER RESULT] nodes={len(result)}")

        return result


# ==============================
# FACTORY
# ==============================
class ParserFactory:
    _parsers: Dict[str, BaseParser] = {}

    @classmethod
    def get_parser(cls, file_path: str):
        if not cls._parsers:
            cls._register_parsers()

        ext = Path(file_path).suffix.lower()
        parser = cls._parsers.get(ext)

        if not parser:
            return None

        # ✅ IMPORTANT: return raw parser (no breaking wrapper)
        return parser

    @classmethod
    def _register_parsers(cls):
        parsers = [
            PythonParser(),
            JavaParser(),
            JavaScriptParser(),
            CParser(),
            CppParser(),
            GoParser(),
            RustParser(),
        ]

        for p in parsers:
            for ext in p.supported_extensions():
                cls._parsers[ext] = p