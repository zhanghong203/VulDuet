# 将规则转化成文档

import json
from pathlib import Path

import numpy as np
from FlagEmbedding import FlagModel
from tqdm import tqdm


def format_cert_rule_to_text(rule_dict: dict) -> str:
    """
    :param rule_dict: 单条规则字典
    :return: 格式化多行字符串
    """
    lines = []

    # 2. Category

    """
    lines.append("Category:")

    cat_raw = rule_dict["category"]
    if "(" in cat_raw:
        cat = cat_raw.split("(")[1].replace(")", "").strip()
    else:
        cat = cat_raw
    lines.append(cat)
    lines.append("")
    """

    # 3. Rule 规则原文
    lines.append("Rule:")
    lines.append(rule_dict["rule_full_title"])
    lines.append("")

    # 4. Risk 风险描述
    lines.append("Risk:")
    risk_desc = rule_dict["extension_info"].get("risk_description", rule_dict["extension_info"].get("vulnerability_harm", "未描述风险危害"))
    lines.append(risk_desc)
    lines.append("")

    # 拼接换行
    return "\n".join(lines)


def process_data(input_json_path, output_json_path=None):
    """
    读取原始规则JSON，处理为目标存储格式
    :param input_json_path: 原始规则文件路径
    :param output_json_path: 可选，输出保存路径
    :return: 目标格式列表 [{"rule_id":"", "document":""}, ...]
    """
    # 读取原始数组数据
    with open(input_json_path, "r", encoding="utf-8") as f:
        raw_rules = json.load(f)

    # 构造目标结构
    result_list = []
    for item in raw_rules:
        rid = item["rule_id"]
        doc_text = format_cert_rule_to_text(item)
        result_list.append({
            "rule_id": rid,
            "document": doc_text
        })

    # 如果传入输出路径，直接写入JSON文件
    if output_json_path is not None:
        with open(output_json_path, "w", encoding="utf-8") as fw:
            json.dump(result_list, fw, ensure_ascii=False, indent=4)

    return result_list


if __name__ == "__main__":
    # ===========================
    # 1. 加载 BGE 模型
    # ===========================
    model = FlagModel(
        "BAAI/bge-large-en-v1.5",
        use_fp16=True
    )
    # ===================== 你的原始知识库数据 =====================
    rule_path = "../data/knowledge/rules.json"
    output_path = "../output/step1/new_documents.json"
    if not Path(output_path).is_file():
        # ===================== 批量转换并打印 =====================
        result_list = process_data(rule_path, output_path)
        for idx, content in enumerate(result_list, 1):
            print(f"========== Rule {idx} ==========")
            print(content)
            print("\n\n")
    # ===========================
    # 2. 读取规则文档
    # ===========================
    with open(output_path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    # ===========================
    # 3. 逐条生成 Embedding
    # ===========================
    embeddings = []
    mapping = []

    for idx, rule in enumerate(tqdm(rules, desc="Embedding Rules")):
        document = rule["document"]

        # FlagEmbedding 返回的是 List[np.ndarray]
        embedding = model.encode([document])[0]

        embeddings.append(embedding)

        mapping.append({
            "index": idx,
            "rule_id": rule["rule_id"]
        })
    # ===========================
    # 4. 保存 Embedding
    # ===========================
    embeddings = np.array(embeddings, dtype=np.float32)

    np.save("../output/step2/new_embeddings.npy", embeddings)

    print("=" * 50)
    print("Embedding Finished!")
    print(f"Number of Rules : {len(embeddings)}")
    print(f"Embedding Shape : {embeddings.shape}")
    print("=" * 50)
