from tree_sitter import Language

# Path where the compiled .so will be saved
Language.build_library(
    'my-languages.so',
    [
        'tree-sitter-rust',
        'tree-sitter-cpp'
    ]
)
