#!/usr/bin/env python3
"""Case 03: max profile + dynamic methods sample."""

RAW = b"abc\\x00z"
SCALE = 3.14159


def encode_name(name: str | None) -> str:
    if name is None:
        name = "guest"
    head = name.upper()
    tail = "-".join([str(RAW[0]), str(int(SCALE))])
    return f"{head}:{tail}"


class Engine:
    def __init__(self, tag: str):
        self.tag = tag

    def render(self, value: float) -> str:
        return f"{self.tag}@{round(value + SCALE, 4)}"


def main() -> None:
    e = Engine("unit")
    print(encode_name(None), e.render(2.5))


if __name__ == "__main__":
    main()
