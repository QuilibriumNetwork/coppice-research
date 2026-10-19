"""Generate/check deterministic research vectors; not NTRU/Falcon test vectors."""
import json
from pathlib import Path
import sys
from core import SecretFrontier, header_material
from wire import pack, Merkle


def generate():
    examples = [None, False, True, 0, 2**64 - 1, b"", b"abc", "coppice",
                (b"a", 7, True), {"b": 2, "a": 1}]
    tree = Merkle([pack(i) for i in range(3)], b"research vector context")
    frontier = SecretFrontier(b"s" * 32, b"research vector era", 5)
    openings = []
    for index in (0, 4, 1, 3, 2):
        leaf = frontier.open(index)
        openings.append({"index": index, "leaf": leaf.hex(),
                         "frontier": [[depth, position, value.hex()]
                                      for (depth, position), value in sorted(frontier.nodes.items())]})
    return {
        "format": "coppice-research-1; candidate tagged encoding, NOT a production wire format",
        "encoding": [{"python_value": repr(value), "hex": pack(value).hex()} for value in examples],
        "merkle": {"context": b"research vector context".hex(), "count": 3,
                   "leaves": [pack(i).hex() for i in range(3)], "root": tree.root.hex(),
                   "paths": [[s.hex() for s in tree.proof(i).siblings] for i in range(3)]},
        "secret_tree": {"seed": (b"s" * 32).hex(), "era": b"research vector era".hex(),
                        "leaves": 5, "openings": openings},
        "header_material": [{"ciphertext": body.hex(),
                             "key_nonce": header_material(b"h" * 32, b"public fields", body).hex()}
                            for body in (b"first encrypted body", b"second encrypted body")],
    }


if __name__ == "__main__":
    path = Path(__file__).with_name("vectors.json")
    expected = json.dumps(generate(), indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if path.read_text() != expected:
            raise SystemExit("Research vectors differ; review the format/state change")
        print("Research vectors match")
    else:
        path.write_text(expected)
        print(f"Wrote {path}")
