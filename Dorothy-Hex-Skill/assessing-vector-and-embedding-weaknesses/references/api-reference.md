# API and Command Reference

## sentence-transformers (embedding generation)
| Call | Purpose |
|------|---------|
| `SentenceTransformer("all-MiniLM-L6-v2")` | Load an embedding model (384-dim) |
| `model.encode([texts])` | Return numpy array of embeddings |
| `model.encode(text, normalize_embeddings=True)` | L2-normalized vectors (for cosine) |

## scikit-learn similarity
| Call | Purpose |
|------|---------|
| `cosine_similarity(a, b)` | Pairwise cosine similarity matrix |

## Qdrant client (qdrant-client)
| Call | Purpose |
|------|---------|
| `QdrantClient(url="http://localhost:6333")` | Connect |
| `client.get_collection(name)` | Inspect vector size + distance metric |
| `client.count(name)` | Corpus size |
| `client.search(collection_name, query_vector, limit, query_filter)` | k-NN search with optional filter |
| `client.upsert(name, points=[PointStruct(id, vector, payload)])` | Insert/update points |
| `Filter(must=[FieldCondition(key, match=MatchValue(value))])` | Metadata filter (tenant isolation) |

## Chroma (chromadb)
| Call | Purpose |
|------|---------|
| `chromadb.Client()` / `PersistentClient(path)` | Connect |
| `collection.query(query_embeddings=[...], n_results=k, where={...})` | k-NN with metadata filter |
| `collection.add(ids, embeddings, metadatas, documents)` | Insert |

## Pinecone (pinecone-client)
| Call | Purpose |
|------|---------|
| `Pinecone(api_key=...)` | Connect |
| `index.query(vector=..., top_k=k, namespace="tenant", filter={...})` | k-NN; namespace = tenant boundary |
| `index.upsert(vectors=[(id, vec, meta)], namespace=...)` | Insert |

## Assessment metrics
| Metric | Meaning |
|--------|---------|
| Inversion cosine | Similarity between reconstructed candidate and target vector; high = recoverable. |
| Membership delta | top-1 score(in-corpus query) − top-1 score(control query); large positive = membership leak. |
| Poison dominance | Fraction of unrelated queries returning the poison chunk in top_k. |
| Cross-tenant count | Number of foreign-tenant rows returned to a tenant query (should be 0). |

## vec2text (research baseline)
| Call | Purpose |
|------|---------|
| `vec2text.load_pretrained_corrector("gtr-base")` | Load inversion corrector for compatible embedder |
| `vec2text.invert_embeddings(embeddings, corrector)` | Reconstruct text from embeddings |
