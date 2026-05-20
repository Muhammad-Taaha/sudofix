from parser.ast_nodes import UnifiedNode
class GenericChunker:
    def chunk(self, root: UnifiedNode):
        return [{
            "content": root.code,
            "file_path": root.file_path,
            "chunk_type": "full_file",
            "start_line": root.start_line,
            "end_line": root.end_line,
            "metadata": {
                "language": root.language
            },
            "nodes": [root],
        }]