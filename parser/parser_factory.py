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

class ParserFactory:
    _parsers: Dict[str, BaseParser] = {}

    @classmethod
    def get_parser(cls, file_path: str) -> Optional[BaseParser]:
        ext = Path(file_path).suffix.lower()
        if not cls._parsers:
            cls._register_parsers()
        for parser_ext, parser in cls._parsers.items():
            if ext in parser.supported_extensions():
                return parser
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