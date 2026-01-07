# modules/ai/ai_embedding.py

from sentence_transformers import SentenceTransformer
import threading

class EmbeddingModel:
    _instance = None
    _lock = threading.Lock()

    @staticmethod
    def get():
        """Singleton loader for embedding model."""
        if EmbeddingModel._instance is None:
            with EmbeddingModel._lock:
                if EmbeddingModel._instance is None:
                    EmbeddingModel._instance = SentenceTransformer("BAAI/bge-large-en-v1.5")
        return EmbeddingModel._instance

def embed_text(text: str):
    model = EmbeddingModel.get()
    return model.encode(text).tolist()
