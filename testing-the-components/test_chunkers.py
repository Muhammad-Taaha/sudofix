#!/usr/bin/env python3
"""
Quick test to verify chunker integration works properly.
Tests the complete parsing pipeline.
"""
import sys
from pathlib import Path
from parser.repo_parser import RepoParser
from parser.detectors import FileDetector

def test_chunker_integration():
    """Test that chunkers work with repo_parser"""
    
    repo_path = Path(".").resolve()
    print(f"📁 Testing repo at: {repo_path}\n")
    
    # Initialize components
    parser = RepoParser(str(repo_path))
    detector = FileDetector(str(repo_path))
    
    # Test files to parse
    test_files = [
        "parser/repo_parser.py",
        "main.py",
        "requirements.txt",
        "README.md" if Path("README.md").exists() else None,
    ]
    
    test_files = [f for f in test_files if f and Path(f).exists()]
    
    print(f"🔍 Testing {len(test_files)} files...\n")
    
    for file_path in test_files:
        full_path = str(Path(file_path).resolve())
        
        # 1. Detect metadata
        metadata = detector.get_file_metadata(full_path)
        print(f"\n📄 File: {file_path}")
        print(f"   Language: {metadata['language']}")
        print(f"   Strategy: {metadata['parse_strategy']}")
        
        # 2. Parse file
        chunks = parser.parse_file(metadata)
        
        if chunks:
            print(f"   ✅ Parsed into {len(chunks)} chunks")
            for i, chunk in enumerate(chunks[:2]):  # Show first 2
                print(f"      Chunk {i+1}: Lines {chunk['start_line']}-{chunk['end_line']} ({len(chunk['content'])} chars)")
                if chunk.get('symbol'):
                    print(f"               Symbol: {chunk['symbol']}")
        else:
            print(f"   ⚠️  No chunks generated")
    
    print("\n✅ Test complete!")

if __name__ == "__main__":
    try:
        test_chunker_integration()
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
