#!/usr/bin/env python3
"""Case 02: stealth class-heavy sample."""


class Wallet:
    def __init__(self, owner: str):
        self.owner = owner
        self.balance = 0

    def deposit(self, amount: int) -> None:
        self.balance += amount

    def withdraw(self, amount: int) -> bool:
        if amount > self.balance:
            return False
        self.balance -= amount
        return True

    def snapshot(self) -> dict:
        return {
            "owner": self.owner,
            "balance": self.balance,
            "ok": self.balance >= 0,
        }


def run_demo() -> None:
    w = Wallet("bob")
    w.deposit(30)
    w.withdraw(7)
    print(w.snapshot())


if __name__ == "__main__":
    run_demo()
