from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/durable.py")


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    start_marker = "    def enqueue(\n"
    end_marker = "    def get("
    if source.count(start_marker) != 1:
        raise SystemExit(
            "durable patch refused: expected one DurableOutbox.enqueue definition"
        )
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    block = source[start:end]
    signature_anchor = "    def enqueue(\n        self,\n"
    if block.count(signature_anchor) != 1:
        raise SystemExit("durable patch refused: enqueue signature shape changed")
    transactional = block.replace(
        signature_anchor,
        "    def enqueue_in_transaction(\n        self,\n        connection: sqlite3.Connection,\n",
        1,
    )
    transaction_line = "        with self.database.transaction() as connection:\n"
    if transactional.count(transaction_line) != 1:
        raise SystemExit("durable patch refused: enqueue transaction owner changed")
    prefix, body = transactional.split(transaction_line, 1)
    dedented: list[str] = []
    for line in body.splitlines(keepends=True):
        if line.startswith("            "):
            dedented.append(line[4:])
        elif line.strip():
            raise SystemExit(
                "durable patch refused: unexpected indentation in enqueue body"
            )
        else:
            dedented.append(line)
    transactional = prefix + "".join(dedented)
    wrapper = '''    def enqueue(
        self,
        *,
        effect_id: str,
        topic: str,
        payload: Mapping[str, Any],
        max_attempts: int,
        available_at: str | None = None,
        actor: str,
    ) -> DurableEffect:
        with self.database.transaction() as connection:
            return self.enqueue_in_transaction(
                connection,
                effect_id=effect_id,
                topic=topic,
                payload=payload,
                max_attempts=max_attempts,
                available_at=available_at,
                actor=actor,
            )

'''
    patched = source[:start] + transactional + wrapper + source[end:]
    if patched.count("    def enqueue_in_transaction(\n") != 1:
        raise SystemExit("durable patch refused: transactional enqueue duplication")
    if patched.count("    def enqueue(\n") != 1:
        raise SystemExit("durable patch refused: enqueue wrapper duplication")
    PATH.write_text(patched, encoding="utf-8")
    print("moved the existing enqueue logic under one caller-owned transaction seam")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
