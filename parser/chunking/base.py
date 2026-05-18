from abc import ABC, abstractclassmethod

from typing import List, Dict


class BaseChunkStategy(ABC):
    @abstractclassmethod
    def chunk(self, content: str, file_path: str, meta_data: Dict) -> List(Dict):
        pass
