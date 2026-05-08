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
### creating a debug for the parser factory

class DebugParser:
    def __init__(self, parser):
        self.parser = parser

    def parse(self, file_path):
        print(f"\n🧪 [PARSER DEBUG] {file_path}")
        result = self.parser.parse(file_path)
        print(f"🧪 [PARSER RESULT] {type(result)} | length={len(result) if result else 0}")
        result = self.parser.parse(file_path)
        flat = result
        print(f"🧪 [PARSER RESULT] {type(result)} | nodes={len(flat)}")

   
class ParserFactory:
    _parsers: Dict[str, BaseParser] = {}

    @classmethod
    def get_parser(cls, file_path: str) -> Optional[BaseParser]:
        ext = Path(file_path).suffix.lower()

        if not cls._parsers:
            cls._register_parsers()

        for parser_ext, parser in cls._parsers.items():
            if ext in parser.supported_extensions():
                return DebugParser(parser)   # ✅ WRAPPED HERE

        return None

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