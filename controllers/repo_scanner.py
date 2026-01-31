# there are two things that  can do for scanning the repo first is to use the hook
# the second one is to make the custom
import os
from pathlib import Path
from typing import List, Dict
from parser.file_walker import RepoWalker
from parser.detectors import FileDetector
from parser.repo_parser import RepoParser
class RepoScanner:
    def __init__(self):
        pass 
    def local_scanner(self):
        pass
    def git_hub_webhook_scanner(self):
        pass 
    