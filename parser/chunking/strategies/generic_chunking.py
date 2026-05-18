class TextChunker:
    def __init__(self, chunk_size=500, overlap=50, strategy="char"):
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.strategy = strategy

    def chunk(self, text):
        if self.strategy == "char":
            return self._char_chunk(text)
        elif self.strategy == "word":
            return self._word_chunk(text)
        elif self.strategy == "sentence":
            return self._sentence_chunk(text)
        else:
            raise ValueError("Invalid strategy")

    # -------- CHAR CHUNKING --------
    def _char_chunk(self, text):
        chunks = []
        start = 0
        length = len(text)

        while start < length:
            end = start + self.chunk_size
            chunk = text[start:end]
            chunks.append(chunk)

            start = end - self.overlap

        return chunks

    # -------- WORD CHUNKING --------
    def _word_chunk(self, text):
        words = text.split()
        chunks = []
        start = 0

        while start < len(words):
            end = start + self.chunk_size
            chunk = " ".join(words[start:end])
            chunks.append(chunk)

            start = end - self.overlap

        return chunks

    # -------- SENTENCE CHUNKING --------
    def _sentence_chunk(self, text):
        sentences = text.split(". ")
        chunks = []
        current_chunk = []

        for sentence in sentences:
            current_chunk.append(sentence)

            if len(" ".join(current_chunk)) >= self.chunk_size:
                chunks.append(". ".join(current_chunk))
                # overlap sentences
                current_chunk = current_chunk[-self.overlap:]

        if current_chunk:
            chunks.append(". ".join(current_chunk))

        return chunks
