"""
Backtest v5 : traduction ALGORITHMIQUE, et INTERPRÉTÉE, de la logique de Thami Kabbaj.

ATTENTION - ce que ce fichier est et n'est pas
  Les livres de Thami Kabbaj (Psychologie des grands traders, L'art du trading, Agir,
  Gérer vos émotions en Bourse...) n'étaient pas consultables ici : seules des fiches,
  résumés et avis de lecteurs l'étaient. Aucune règle chiffrée (périodes, stops, taille
  de position) n'a pu en être extraite. Ce fichier encode donc :
    * ce que les sources secondaires attribuent à l'auteur :
        - un biais « acheteur si RSI > 50, hors marché sinon » (un seul blog, non recoupé) ;
        - la gestion du risque / du capital comme condition de survie ;
        - couper les pertes, ne pas se laisser piéger par les biais (dissonance cognitive,
          aversion aux pertes) ;
    * des PARAMÈTRES CHOISIS PAR NOUS (RSI 14, stop 8 %, risque 2 %), non issus de ses livres.
  Les résultats évaluent cette interprétation, pas la méthode de l'auteur.

Usage:
    python3 -I backtest_v5.py data/SP500.csv --years 10 [--stop 0.08] [--risk 0.02]
        [--rsi-n 14] [--cash-rate 0.03] [--fee 0.001] [--lag 1]

Cadre commun identique à la v4 : versement mensuel sur une poche cash rémunérée,
signal à la clôture de J exécuté à J+lag, frais par côté, mêmes dates pour tous.

Stratégies :
  dca        Référence : investit chaque versement tout de suite.
  trend200   Référence v4 : investi si Close > MM200.
  rsi50      Investi (100 %) si RSI(n) > 50, sinon cash.
  k_stop     rsi50 + discipline anti-biais : stop de perte à --stop sous le prix d'entrée
             (sur clôtures) ; après un stop, pas de ré-entrée tant que le RSI n'est pas
             repassé sous 50 puis au-dessus (pas de « revenge trading »).
  k_risk     k_stop + taille de position par le risque : poids = min(1, --risk / --stop)
             (2 % / 8 % = 25 % du patrimoine) ; le reste reste en cash.
"""
import argparse
import csv
from datetime import date, timedelta

ALL = ["dca", "trend200", "rsi50", "k_stop", "k_risk"]


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


def rsi(values, n=2):
    """RSI de Wilder."""
    out = [None] * len(values)
    if len(values) <= n:
        return out
    gains = [max(values[i] - values[i - 1], 0.0) for i in range(1, n + 1)]
    losses = [max(values[i - 1] - values[i], 0.0) for i in range(1, n + 1)]
    ag, al = sum(gains) / n, sum(losses) / n
    out[n] = 100.0 if al == 0 else 100.0 - 100.0 / (1 + ag / al)
    for i in range(n + 1, len(values)):
        ch = values[i] - values[i - 1]
        ag = (ag * (n - 1) + max(ch, 0.0)) / n
        al = (al * (n - 1) + max(-ch, 0.0)) / n
        out[i] = 100.0 if al == 0 else 100.0 - 100.0 / (1 + ag / al)
    return out


def month_key(d):
    return (d.year, d.month)


def month_ends(dates):
    return [i == len(dates) - 1 or month_key(dates[i + 1]) != month_key(dates[i]) for i in range(len(dates))]


def xirr(flows):
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



# ---------------------------------------------------------------- signaux (poids cibles 0..1)

def w_dca(dates, c):
    return [1.0] * len(c)


def w_trend200(dates, c):
    ma = sma(c, 200)
    return [1.0 if ma[i] is not None and c[i] > ma[i] else 0.0 for i in range(len(c))]


def w_rsi50(dates, c, n):
    r = rsi(c, n)
    return [1.0 if r[i] is not None and r[i] > 50 else 0.0 for i in range(len(c))]


def w_kabbaj(dates, c, n, stop, weight):
    """RSI>50 + stop + pas de ré-entrée après stop avant un retour du RSI sous 50."""
    r = rsi(c, n)
    out, hold, entry, blocked = [], False, 0.0, False
    for i in range(len(c)):
        if r[i] is None:
            out.append(0.0)
            continue
        if r[i] < 50:
            blocked = False  # le signal est « réarmé »
        if hold:
            if c[i] <= entry * (1 - stop) or r[i] < 50:
                if c[i] <= entry * (1 - stop):
                    blocked = True
                hold = False
        elif r[i] > 50 and not blocked:
            hold, entry = True, c[i]
        out.append(weight if hold else 0.0)
    return out


# ---------------------------------------------------------------- simulation

def simulate(dates, c, weights, start, monthly, cash_rate, fee, lag, signal=True):
    """weights[i] : poids cible décidé à la clôture de i, exécuté à i+lag.
    Rééquilibrage vers le poids cible à chaque changement de poids et à chaque versement."""
    n = len(dates)
    lag = lag if signal else 0
    cash, shares = 0.0, 0.0
    flows, buys, sells = [], 0, 0
    seen, prev_d, prev_val, cur_w = set(), None, 0.0, 0.0
    idx, peak, maxdd = 1.0, 1.0, 0.0
    days, expo_sum, total = 0, 0.0, 0.0
    for i in range(n):
        d = dates[i]
        if d < start:
            continue
        if prev_d is not None and cash > 0:
            cash *= (1 + cash_rate) ** ((d - prev_d).days / 365.0)
        prev_d = d
        pre = cash + shares * c[i]
        if prev_val > 0:
            idx *= pre / prev_val
        deposit = month_key(d) not in seen
        if deposit:
            seen.add(month_key(d))
            cash += monthly
            total += monthly
            flows.append((d, -monthly))
        tw = weights[i - lag] if i - lag >= 0 else 0.0
        if tw != cur_w or deposit:
            value = cash + shares * c[i]
            diff = tw * value - shares * c[i]
            if diff > 0:
                diff = min(diff, cash)
                if shares == 0 and diff > 0:
                    buys += 1
                shares += diff * (1 - fee) / c[i]
                cash -= diff
            elif diff < 0:
                sold = min(-diff, shares * c[i])
                shares -= sold / c[i]
                cash += sold * (1 - fee)
                if tw == 0 and shares <= 1e-12:
                    shares = 0.0
                    sells += 1
            cur_w = tw
        val = cash + shares * c[i]
        prev_val = val
        peak = max(peak, idx)
        maxdd = max(maxdd, 1 - idx / peak)
        days += 1
        expo_sum += (shares * c[i] / val) if val else 0.0
    final = prev_val
    flows.append((dates[-1], final))
    return {"final": final, "mult": final / total, "irr": xirr(flows), "maxdd": maxdd,
            "expo": expo_sum / days if days else 0.0, "buys": buys, "sells": sells}


def fmt(label, r):
    return (f"{label:<12}{r['final']:>10,.0f}{r['mult']:>7.2f}{r['irr']:>8.1%}{r['maxdd']:>8.0%}"
            f"{r['expo']:>7.0%}{r['buys']:>8}{r['sells']:>8}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("files", nargs="+")
    p.add_argument("--monthly", type=float, default=500.0)
    p.add_argument("--years", type=int, default=10)
    p.add_argument("--cash-rate", type=float, default=0.03)
    p.add_argument("--fee", type=float, default=0.001)
    p.add_argument("--lag", type=int, default=1)
    p.add_argument("--rsi-n", type=int, default=14)
    p.add_argument("--stop", type=float, default=0.08, help="stop de perte (0.08 = 8 %%) - choix de l'outil")
    p.add_argument("--risk", type=float, default=0.02, help="risque par position (0.02 = 2 %%) - choix de l'outil")
    p.add_argument("--strategies", default=",".join(ALL))
    a = p.parse_args()
    strategies = [s.strip() for s in a.strategies.split(",") if s.strip()]
    for s in strategies:
        if s not in ALL:
            p.error(f"stratégie inconnue : {s} (choix : {', '.join(ALL)})")

    data = [dict(load_csv(f)) for f in a.files]
    dates = sorted(set.intersection(*[set(d) for d in data]))
    closes = [[d[x] for x in dates] for d in data]
    last = dates[-1]
    start = date(last.year - a.years, last.month, last.day) + timedelta(days=1)
    wk = min(1.0, a.risk / a.stop)

    print(f"Période : {start} -> {last} | {a.monthly:.0f} €/mois | cash {a.cash_rate:.1%} | frais {a.fee:.2%}/côté | exécution J+{a.lag}")
    print(f"Paramètres choisis par l'outil (pas par l'auteur) : RSI({a.rsi_n}), stop {a.stop:.0%}, risque {a.risk:.0%} -> poids k_risk {wk:.0%}")
    print("Colonnes : valeur finale, multiple, TRI, drawdown max, exposition moyenne, achats, ventes\n")
    header = f"{'Stratégie':<12}{'Final':>10}{'Mult.':>7}{'TRI':>8}{'MaxDD':>8}{'Expo':>7}{'Achats':>8}{'Ventes':>8}"
    for f, c in zip(a.files, closes):
        name = f.split("/")[-1].rsplit(".", 1)[0]
        nmonths = len({(d.year, d.month) for d in dates if d >= start})
        print(f"== {name} (versé {a.monthly * nmonths:,.0f})")
        print(header)
        for s in strategies:
            if s == "dca":
                w = w_dca(dates, c)
            elif s == "trend200":
                w = w_trend200(dates, c)
            elif s == "rsi50":
                w = w_rsi50(dates, c, a.rsi_n)
            elif s == "k_stop":
                w = w_kabbaj(dates, c, a.rsi_n, a.stop, 1.0)
            else:
                w = w_kabbaj(dates, c, a.rsi_n, a.stop, wk)
            print(fmt(s, simulate(dates, c, w, start, a.monthly, a.cash_rate, a.fee, a.lag, signal=(s != "dca"))))
        print()


if __name__ == "__main__":
    main()
