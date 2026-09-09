# 建立FAISS向量库

import json
import numpy as np
import faiss


def build_faiss_index(
        embedding_path,
        document_path,
        index_path,
        mapping_path
):
    """
    根据规则向量建立FAISS索引
    """

    # ==========================
    # 1. 读取Embedding
    # ==========================
    print("Loading embeddings...")

    embeddings = np.load(embedding_path).astype(np.float32)

    print(f"Embedding Shape : {embeddings.shape}")

    # ==========================
    # 2. 读取规则文档
    # ==========================
    print("Loading rule documents...")

    with open(document_path, "r", encoding="utf-8") as f:
        rules = json.load(f)

    if len(rules) != embeddings.shape[0]:
        raise ValueError(
            "规则数量与Embedding数量不一致！"
        )

    # ==========================
    # 3. 创建FAISS索引
    # ==========================
    dimension = embeddings.shape[1]

    # IndexFlatIP = Inner Product
    # 如果Embedding已经Normalize
    # Inner Product == Cosine Similarity
    index = faiss.IndexFlatIP(dimension)

    # ==========================
    # 4. 加入所有规则向量
    # ==========================
    index.add(embeddings)

    print(f"Indexed vectors : {index.ntotal}")

    # ==========================
    # 5. 保存FAISS索引
    # ==========================
    faiss.write_index(index, index_path)

    print(f"FAISS index saved to : {index_path}")

    # ==========================
    # 6. 保存Mapping
    # ==========================
    mapping = []

    for idx, rule in enumerate(rules):

        mapping.append({

            "index": idx,

            "rule_id": rule["rule_id"]

        })

    with open(mapping_path, "w", encoding="utf-8") as f:

        json.dump(
            mapping,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(f"Mapping saved to : {mapping_path}")

    print("=" * 50)
    print("Build FAISS Successfully!")
    print("=" * 50)


if __name__ == "__main__":
    build_faiss_index(
        embedding_path="../output/step2/new_embeddings.npy",
        document_path="../output/step1/new_documents.json",
        index_path="../output/retrival/new_rule.index",
        mapping_path="../output/step1/new_mapping.json"
    )
