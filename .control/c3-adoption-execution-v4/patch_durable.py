from __future__ import annotations

import ast
from pathlib import Path


PATH = Path("src/starcom/durable.py")


def _method(tree: ast.AST, class_name: str, method_name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name == method_name:
                    return child
    raise SystemExit(f"durable patch refused: {class_name}.{method_name} not found")


def _indent_block(lines: list[str], amount: int) -> list[str]:
    prefix = " " * amount
    return [prefix + line if line.strip() else line for line in lines]


def _dedent_block(lines: list[str], amount: int) -> list[str]:
    prefix = " " * amount
    result: list[str] = []
    for line in lines:
        if not line.strip():
            result.append(line)
        elif line.startswith(prefix):
            result.append(line[amount:])
        else:
            raise SystemExit(
                "durable patch refused: caller-owned enqueue body indentation changed"
            )
    return result


def _replace_enqueue(source: str) -> str:
    tree = ast.parse(source)
    enqueue = _method(tree, "DurableOutbox", "enqueue")
    lines = source.splitlines(keepends=True)
    block = lines[enqueue.lineno - 1 : enqueue.end_lineno]

    signature_end = None
    for index, line in enumerate(block):
        if line.startswith("    ) -> EffectRecord:"):
            signature_end = index
            break
    if signature_end is None:
        raise SystemExit("durable patch refused: enqueue signature changed")

    signature = block[: signature_end + 1]
    body = block[signature_end + 1 :]
    if not signature[0].startswith("    def enqueue("):
        raise SystemExit("durable patch refused: enqueue definition changed")
    if len(signature) < 2 or signature[1].strip() != "self,":
        raise SystemExit("durable patch refused: enqueue self parameter changed")

    transaction_index = None
    for index, line in enumerate(body):
        if line == "        with self.database.transaction() as connection:\n":
            transaction_index = index
            break
    if transaction_index is None:
        raise SystemExit("durable patch refused: enqueue transaction owner changed")

    preamble = body[:transaction_index]
    transactional_body = _dedent_block(body[transaction_index + 1 :], 4)
    transactional_signature = list(signature)
    transactional_signature[0] = transactional_signature[0].replace(
        "def enqueue(", "def enqueue_in_transaction(", 1
    )
    transactional_signature.insert(2, "        connection: sqlite3.Connection,\n")
    transactional = transactional_signature + preamble + transactional_body

    wrapper = [
        "    def enqueue(\n",
        "        self,\n",
        "        *,\n",
        "        effect_id: str | None = None,\n",
        "        topic: str,\n",
        "        payload: Mapping[str, Any],\n",
        "        max_attempts: int = 3,\n",
        "        available_at: str | None = None,\n",
        "        actor: str,\n",
        "        occurred_at: str | None = None,\n",
        "    ) -> EffectRecord:\n",
        "        with self.database.transaction() as connection:\n",
        "            return self.enqueue_in_transaction(\n",
        "                connection,\n",
        "                effect_id=effect_id,\n",
        "                topic=topic,\n",
        "                payload=payload,\n",
        "                max_attempts=max_attempts,\n",
        "                available_at=available_at,\n",
        "                actor=actor,\n",
        "                occurred_at=occurred_at,\n",
        "            )\n",
        "\n",
    ]

    replacement = transactional + ["\n"] + wrapper
    return "".join(lines[: enqueue.lineno - 1] + replacement + lines[enqueue.end_lineno :])


def _replace_claim(source: str) -> str:
    tree = ast.parse(source)
    claim = _method(tree, "DurableOutbox", "claim")
    lines = source.splitlines(keepends=True)
    block = lines[claim.lineno - 1 : claim.end_lineno]

    signature_end = None
    for index, line in enumerate(block):
        if line.startswith("    ) -> list[EffectLease]:"):
            signature_end = index
            break
    if signature_end is None:
        raise SystemExit("durable patch refused: claim signature changed")
    if any("topic: str | None" in line for line in block[: signature_end + 1]):
        raise SystemExit("durable patch refused: topic filter already exists")
    block.insert(signature_end, "        topic: str | None = None,\n")

    validation_anchor = '        worker_id = self._required_text(worker_id, "worker_id")\n'
    try:
        validation_index = block.index(validation_anchor)
    except ValueError as exc:
        raise SystemExit("durable patch refused: claim worker validation changed") from exc
    block[validation_index + 1 : validation_index + 1] = [
        "        if topic is not None:\n",
        '            topic = self._required_text(topic, "topic")\n',
    ]

    claim_tree = ast.parse("class Holder:\n" + "".join(_indent_block(block, 4)))
    claim_method = _method(claim_tree, "Holder", "claim")
    rows_assign = None
    for node in ast.walk(claim_method):
        if isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == "rows"
                for target in node.targets
            ):
                rows_assign = node
                break
    if rows_assign is None or rows_assign.end_lineno is None:
        raise SystemExit("durable patch refused: claim rows query not found")

    # AST line numbers include the synthetic class line and four-space indentation.
    start = rows_assign.lineno - 2
    end = rows_assign.end_lineno - 1
    query_replacement = [
        '            conditions = ["status = ?", "available_at <= ?"]\n',
        "            parameters: list[object] = [\n",
        "                EffectStatus.PENDING.value,\n",
        "                now,\n",
        "            ]\n",
        "            if topic is not None:\n",
        '                conditions.append("topic = ?")\n',
        "                parameters.append(topic)\n",
        "            parameters.append(limit)\n",
        "            rows = connection.execute(\n",
        '                "SELECT * FROM durable_effects WHERE "\n',
        '                + " AND ".join(conditions)\n',
        '                + " ORDER BY available_at, created_at, effect_id LIMIT ?",\n',
        "                tuple(parameters),\n",
        "            ).fetchall()\n",
    ]
    block[start:end] = query_replacement
    return "".join(lines[: claim.lineno - 1] + block + lines[claim.end_lineno :])


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    if "def enqueue_in_transaction(" in source:
        raise SystemExit("durable patch refused: transactional enqueue already exists")
    source = _replace_enqueue(source)
    source = _replace_claim(source)
    ast.parse(source)
    if source.count("    def enqueue_in_transaction(\n") != 1:
        raise SystemExit("durable patch refused: transactional enqueue count mismatch")
    if source.count("    def enqueue(\n") != 1:
        raise SystemExit("durable patch refused: enqueue wrapper count mismatch")
    if source.count("        topic: str | None = None,\n") != 1:
        raise SystemExit("durable patch refused: claim topic filter count mismatch")
    PATH.write_text(source, encoding="utf-8")
    print("added caller-owned durable enqueue and topic-filtered claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
