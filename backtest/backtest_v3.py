"""
[v3 - piste 1] Variante : intérêts sur le cash en attente (--cash-rate), fraction DCA optionnelle (--frac).
Backtest : DCA mensuel conditionnel à la MM200 daily.

Usage:
    python3 -I backtest.py data/SP500.csv data/MSCI_World.csv data/MSFT.csv data/META.csv \
        --monthly 500 --years 10 --sell-band 0.10

Format attendu des CSV (export Yahoo Finance / Investing / Stooq) :
    Date,Close          (Date au format AAAA-MM-JJ ; Close = cours ajusté des dividendes si possible)

Stratégie testée (par actif) :
  - Chaque mois, 'monthly' € sont versés sur une poche cash.
  - ACHAT  : chaque jour où Close < MM200 daily, la poche cash est investie.
  - VENTE  : chaque jour où Close > MM200 * (1 + sell_band), la position est vendue.
  - Référence 1 : DCA mensuel pur (investit chaque mois, sans condition).
  - Référence 2 : buy & hold de l'actif (même total versé, investi au fil des mois).
Métriques : valeur finale, total versé, multiple, TRI annualisé (XIRR sur flux mensuels).
"""
import argparse
import csv
import math
from datetime import date, timedelta


def load_csv(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                d = date.fromisoformat(r["Date"][:10])
                c = float(r["Close"])
            except (KeyError, ValueError):
                continue
            rows.append((d, c))
    rows.sort()
    return rows


def sma(values, n):
    out = [None] * len(values)
    s = 0.0
    for i, v in enumerate(values):
        s += v
        if i >= n:
            s -= values[i - n]
        if i >= n - 1:
            out[i] = s / n
    return out


def month_key(d):
    return (d.year, d.month)


def xirr(flows):
    """flows: list of (date, amount) ; négatif = versement, positif = valeur finale."""
    if not flows:
        return float("nan")
    t0 = flows[0][0]

    def npv(r):
        return sum(a / (1 + r) ** ((d - t0).days / 365.25) for d, a in flows)

    lo, hi = -0.99, 10.0
    f_lo, f_hi = npv(lo), npv(hi)
    if f_lo * f_hi > 0:
        return float("nan")
    for _ in range(200):
        mid = (lo + hi) / 2
        f_mid = npv(mid)
        if f_lo * f_mid <= 0:
            hi, f_hi = mid, f_mid
        else:
            lo, f_lo = mid, f_mid
    return (lo + hi) / 2


def run(rows, monthly, ma_n, sell_band, start, frac=0.0, cash_rate=0.0):
    closes = [c for _, c in rows]
    ma = sma(closes, ma_n)

    # Stratégie conditionnelle
    cash = 0.0
    shares = 0.0
    invested_total = 0.0
    flows_cond = []
    trades = {"buy": 0, "sell": 0}
    seen_months = set()
    prev_d = None
    for i, (d, c) in enumerate(rows):
        if d < start:
            continue
        if prev_d is not None and cash > 0:
            cash *= (1 + cash_rate) ** ((d - prev_d).days / 365.0)  # intérêts composés
        prev_d = d
        if month_key(d) not in seen_months:
            seen_months.add(month_key(d))
            shares += monthly * frac / c
            cash += monthly * (1 - frac)
            invested_total += monthly
            flows_cond.append((d, -monthly))
        if ma[i] is None:
            continue
        if shares > 0 and c > ma[i] * (1 + sell_band):
            cash += shares * c
            shares = 0.0
            trades["sell"] += 1
        if cash > 0 and c < ma[i]:
            shares += cash / c
            cash = 0.0
            trades["buy"] += 1
    last_date, last_close = rows[-1]
    if prev_d is not None and cash > 0:
        cash *= (1 + cash_rate) ** ((last_date - prev_d).days / 365.0)
    final_cond = shares * last_close + cash
    flows_cond.append((last_date, final_cond))

    # Référence 1 : DCA mensuel pur
    sh_dca = 0.0
    flows_dca = []
    seen = set()
    for d, c in rows:
        if d < start:
            continue
        if month_key(d) not in seen:
            seen.add(month_key(d))
            sh_dca += monthly / c
            flows_dca.append((d, -monthly))
    final_dca = sh_dca * last_close
    flows_dca.append((last_date, final_dca))

    total = invested_total
    return {
        "total_verse": total,
        "cond_final": final_cond,
        "cond_mult": final_cond / total,
        "cond_irr": xirr(flows_cond),
        "cond_exposition_finale": (shares * last_close) / final_cond if final_cond else 0,
        "trades": trades,
        "dca_final": final_dca,
        "dca_mult": final_dca / total,
        "dca_irr": xirr(flows_dca),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("files", nargs="+")
    p.add_argument("--monthly", type=float, default=500.0)
    p.add_argument("--years", type=int, default=10)
    p.add_argument("--ma", type=int, default=200)
    p.add_argument("--frac", type=float, default=0.0, help="part du versement investie tout de suite (0 = comportement d'origine)")
    p.add_argument("--cash-rate", type=float, default=0.0, help="taux annuel du cash en attente (0.03 = 3 %%)")
    p.add_argument("--sell-band", type=float, default=0.10)
    a = p.parse_args()

    last = None
    for f in a.files:
        rows = load_csv(f)
        if last is None:
            last = rows[-1][0]
    start = date(last.year - a.years, last.month, last.day) + timedelta(days=1)

    print(f"Période : {start} -> {last} | DCA {a.monthly} €/mois | MM{a.ma} | vente si > +{a.sell_band:.0%} | fraction DCA {a.frac:.0%} | cash {a.cash_rate:.1%}\n")
    header = f"{'Actif':<14}{'Versé':>10}{'Cond. final':>13}{'Mult.':>7}{'TRI':>8}{'Achats':>8}{'Ventes':>8}{'DCA final':>12}{'Mult.':>7}{'TRI':>8}"
    print(header)
    print("-" * len(header))
    for f in a.files:
        name = f.split("/")[-1].rsplit(".", 1)[0]
        rows = load_csv(f)
        r = run(rows, a.monthly, a.ma, a.sell_band, start, a.frac, a.cash_rate)
        print(
            f"{name:<14}{r['total_verse']:>10,.0f}{r['cond_final']:>13,.0f}{r['cond_mult']:>7.2f}"
            f"{r['cond_irr']:>8.1%}{r['trades']['buy']:>8}{r['trades']['sell']:>8}"
            f"{r['dca_final']:>12,.0f}{r['dca_mult']:>7.2f}{r['dca_irr']:>8.1%}"
        )


if __name__ == "__main__":
    main()
