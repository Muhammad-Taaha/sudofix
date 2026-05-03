from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from .ast_nodes import UnifiedNode


class BaseParser(ABC):  # making an abstract base class named BasedParser

    @abstractmethod
    def parse(self, file_path: str) -> List[UnifiedNodes]:

        # the purpose of this function is to parse a file and return the list of the UnifiedNodes nodes

        pass

    def supported_extensions(self) -> List[str]:
        # this return the list of the supported extensions

        pass
