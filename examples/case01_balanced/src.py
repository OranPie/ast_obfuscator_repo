#!/usr/bin/env python3
"""Case 01: balanced sample."""

from statistics import mean


def normalize(values):
    base = mean(values)
    return [round(v - base, 2) for v in values]


def greet(user: str, scores: list[float]) -> str:
    badge = "gold" if sum(scores) > 25 else "silver"
    return f"hello {user} ({badge}) -> {normalize(scores)}"


if __name__ == "__main__":
    print(greet("alice", [7.5, 8.0, 9.5]))
