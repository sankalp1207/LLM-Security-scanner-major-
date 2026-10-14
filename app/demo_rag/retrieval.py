"""Document retrieval engine using TF-IDF similarity."""

from typing import List, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.demo_rag.documents import Document, get_all_documents


class Retriever:
    """TF-IDF vector space retriever for synthetic corporate documents."""

    def __init__(self, documents: List[Document] | None = None):
        self.documents = documents if documents is not None else get_all_documents()
        self.corpus = [f"{d.title} {d.content}" for d in self.documents]
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        self.doc_matrix = self.vectorizer.fit_transform(self.corpus)

    def retrieve(self, query: str, top_k: int = 3) -> List[Tuple[Document, float]]:
        """Retrieve top_k documents most relevant to query string."""
        if not query.strip():
            return []

        query_vec = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self.doc_matrix).flatten()

        # Sort indices by descending similarity score
        ranked_indices = similarities.argsort()[::-1]

        results: List[Tuple[Document, float]] = []
        for idx in ranked_indices[:top_k]:
            score = float(similarities[idx])
            # Include documents with minimal relevance or top match if all low
            if score > 0.05 or len(results) == 0:
                results.append((self.documents[idx], round(score, 4)))

        return results


# Global retriever instance
default_retriever = Retriever()
