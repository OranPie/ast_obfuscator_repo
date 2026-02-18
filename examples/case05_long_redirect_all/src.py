#!/usr/bin/env python3
"""Long demo source for heavy no-wrap obfuscation with full symbol redirects."""

from statistics import mean, median

TAX_RATE = 0.075
SERVICE_WEIGHTS = [1.0, 0.9, 1.15, 1.05, 0.95]
REGION_OFFSETS = {
    "north": 1.03,
    "south": 0.98,
    "east": 1.01,
    "west": 1.02,
}
SKU_BASE_PRICE = {
    "A": 12.5,
    "B": 18.25,
    "C": 7.75,
    "D": 32.0,
}


class LedgerEntry:
    def __init__(self, customer_id: str, sku: str, quantity: int, service_idx: int) -> None:
        self.customer_id = customer_id
        self.sku = sku
        self.quantity = quantity
        self.service_idx = service_idx

    def subtotal(self) -> float:
        unit = SKU_BASE_PRICE[self.sku]
        return unit * self.quantity


class MonthlyLedger:
    def __init__(self, region: str) -> None:
        self.region = region
        self.entries: list[LedgerEntry] = []

    def add(self, entry: LedgerEntry) -> None:
        self.entries.append(entry)

    def totals(self) -> list[float]:
        region_mul = REGION_OFFSETS.get(self.region, 1.0)
        values: list[float] = []
        for entry in self.entries:
            service_mul = SERVICE_WEIGHTS[entry.service_idx % len(SERVICE_WEIGHTS)]
            values.append(entry.subtotal() * service_mul * region_mul)
        return values


def rolling_average(values: list[float], window: int) -> list[float]:
    if window <= 1:
        return values[:]
    out: list[float] = []
    for idx in range(len(values)):
        left = max(0, idx - window + 1)
        block = values[left : idx + 1]
        out.append(sum(block) / len(block))
    return out


def customer_score(customer_totals: list[float]) -> float:
    if not customer_totals:
        return 0.0
    center = mean(customer_totals)
    middle = median(customer_totals)
    drift = sum(abs(x - center) for x in customer_totals) / len(customer_totals)
    return (center * 0.65 + middle * 0.25) - drift * 0.1


def build_monthly_ledger(seed: int, region: str) -> MonthlyLedger:
    ledger = MonthlyLedger(region)
    sku_order = ["A", "B", "C", "D", "B", "C", "A", "D"]
    for idx in range(1, 37):
        sku = sku_order[(idx + seed) % len(sku_order)]
        qty = 1 + ((idx * 3 + seed) % 5)
        service_idx = (idx * 7 + seed) % 9
        cid = f"C{100 + (idx * 11 + seed) % 17:03d}"
        ledger.add(LedgerEntry(cid, sku, qty, service_idx))
    return ledger


def summarize_by_customer(ledger: MonthlyLedger) -> dict[str, list[float]]:
    grouped: dict[str, list[float]] = {}
    region_mul = REGION_OFFSETS.get(ledger.region, 1.0)
    for entry in ledger.entries:
        service_mul = SERVICE_WEIGHTS[entry.service_idx % len(SERVICE_WEIGHTS)]
        subtotal = entry.subtotal() * service_mul * region_mul
        grouped.setdefault(entry.customer_id, []).append(subtotal)
    return grouped


def build_report(seed: int, region: str) -> dict[str, object]:
    ledger = build_monthly_ledger(seed, region)
    totals = ledger.totals()
    customer_totals = summarize_by_customer(ledger)

    scored = {
        cid: customer_score(rolling_average(values, 3))
        for cid, values in customer_totals.items()
    }
    top_customers = sorted(scored.items(), key=lambda kv: kv[1], reverse=True)[:5]

    gross = sum(totals)
    net = gross * (1.0 + TAX_RATE)

    return {
        "region": region,
        "records": len(ledger.entries),
        "gross": round(gross, 2),
        "net": round(net, 2),
        "avg_ticket": round(mean(totals), 2),
        "top_customers": [(cid, round(score, 3)) for cid, score in top_customers],
    }


def render_report(report: dict[str, object]) -> str:
    top = report["top_customers"]
    top_text = ", ".join(f"{cid}:{score:.3f}" for cid, score in top)
    return (
        f"region={report['region']} records={report['records']} "
        f"gross={report['gross']:.2f} net={report['net']:.2f} "
        f"avg={report['avg_ticket']:.2f} top=[{top_text}]"
    )


def main() -> None:
    report = build_report(11, "north")
    print(render_report(report))


if __name__ == "__main__":
    main()
