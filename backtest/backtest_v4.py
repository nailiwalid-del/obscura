"""
Backtest v4 : comparaison de stratégies de trading classiques (long seulement).

Usage:
    python3 -I backtest_v4.py data/SP500.csv data/MSCI.csv data/MSFT.csv data/META.csv \
        --monthly 500 --years 10 [--strategies dca,trend200,...] [--cash-rate 0.03] [--fee 0.001]

Cadre commun (identique pour toutes les stratégies, donc comparable) :
  - 'monthly' € versés le premier jour de bourse de chaque mois, sur une poche cash.
  - Le cash rapporte --cash-rate (intérêts composés au jour le jour).
  - Chaque stratégie décide « investi » ou « cash » ; investi = tout le patrimoine sur l'actif.
  - Le signal est calculé à la clôture du jour t et exécuté à la clôture de t+lag
    (--lag 1 par défaut : pas de biais d'anticipation). dca n'a pas de signal.
  - Frais : --fee par côté, sur le montant échangé.
  - Dates communes à tous les fichiers (même fenêtre pour tous les actifs).

Stratégies (règles tirées de sources publiques, voir le résumé de session ;
les paramètres sont ceux des publications, non optimisés ici) :
  dca        Référence : investit chaque versement tout de suite.
  trend200   Investi si Close > MM200 (quotidien).
  cross50    Investi si MM50 > MM200 (« golden cross »).
  faber10m   Faber (2007) : décision en fin de mois, investi si Close > MM10 mois (clôtures mensuelles).
  absmom12   Momentum absolu (Antonacci) : fin de mois, investi si rendement 12 mois > taux du cash.
  rsi2       Connors : entrée si Close > MM200 et RSI(2) < 10 ; sortie si Close > MM5.
  rsi2b      Variante : même entrée ; sortie si RSI(2) > 60 (sources divergentes sur la sortie).
  turtle1    Donchian « Turtle système 1 » : entrée au plus haut 20 j, sortie au plus bas 10 j (clôtures).
  turtle2    Donchian « Turtle système 2 » : entrée au plus haut 55 j, sortie au plus bas 20 j (clôtures).
  dualmom    Momentum dual (multi-actifs) : fin de mois, détient l'actif au meilleur rendement 12 mois
             parmi les fichiers donnés s'il bat le cash, sinon cash. Ligne « PORTEFEUILLE ».

Limites : seulement des cours de clôture (pas de plus haut/plus bas intraday, pas d'ATR,
pas de vente à découvert, pas de pyramidage) ; pas d'impôts.
"""
import argparse
import csv
from datetime import date, timedelta

ALL = ["dca", "trend200", "cross50", "faber10m", "absmom12", "rsi2", "rsi2b", "turtle1", "turtle2", "dualmom"]


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


# ---------------------------------------------------------------- signaux
# Chaque fonction renvoie, pour chaque jour i, la décision prise à la clôture de i :
# True = investi, False = cash. (None = pas encore calculable -> cash.)

def sig_trend200(dates, c):
    ma = sma(c, 200)
    return [ma[i] is not None and c[i] > ma[i] for i in range(len(c))]


def sig_cross50(dates, c):
    a, b = sma(c, 50), sma(c, 200)
    return [b[i] is not None and a[i] > b[i] for i in range(len(c))]


def monthly_closes(dates, c):
    """Indices des fins de mois et clôtures correspondantes."""
    me = month_ends(dates)
    idx = [i for i in range(len(dates)) if me[i]]
    return idx, [c[i] for i in idx]


def sig_faber10m(dates, c):
    idx, mc = monthly_closes(dates, c)
    ma = sma(mc, 10)
    out, cur, k = [], False, 0
    for i in range(len(dates)):
        if k < len(idx) and i == idx[k]:
            cur = ma[k] is not None and mc[k] > ma[k]
            k += 1
        out.append(cur)
    return out


def sig_absmom12(dates, c, cash_rate):
    idx, mc = monthly_closes(dates, c)
    out, cur, k = [], False, 0
    for i in range(len(dates)):
        if k < len(idx) and i == idx[k]:
            cur = k >= 12 and (mc[k] / mc[k - 12] - 1) > cash_rate
            k += 1
        out.append(cur)
    return out


def sig_rsi2(dates, c, exit_mode):
    ma200, ma5, r = sma(c, 200), sma(c, 5), rsi(c, 2)
    out, hold = [], False
    for i in range(len(c)):
        if ma200[i] is not None and r[i] is not None:
            if not hold and c[i] > ma200[i] and r[i] < 10:
                hold = True
            elif hold and ((exit_mode == "ma5" and c[i] > ma5[i]) or (exit_mode == "rsi60" and r[i] > 60)):
                hold = False
        out.append(hold)
    return out


def sig_donchian(dates, c, n_in, n_out):
    out, hold = [], False
    for i in range(len(c)):
        if i >= max(n_in, n_out):
            if not hold and c[i] > max(c[i - n_in:i]):
                hold = True
            elif hold and c[i] < min(c[i - n_out:i]):
                hold = False
        out.append(hold)
    return out


def sig_dualmom(dates, closes_list, cash_rate):
    """Renvoie, pour chaque jour, l'indice de l'actif détenu ou None (cash)."""
    me = month_ends(dates)
    idx = [i for i in range(len(dates)) if me[i]]
    out, cur, k = [], None, 0
    for i in range(len(dates)):
        if k < len(idx) and i == idx[k]:
            cur = None
            if k >= 12:
                rets = [cl[idx[k]] / cl[idx[k - 12]] - 1 for cl in closes_list]
                best = max(range(len(rets)), key=lambda j: rets[j])
                if rets[best] > cash_rate:
                    cur = best
            k += 1
        out.append(cur)
    return out


# ---------------------------------------------------------------- simulation

def simulate(dates, closes_list, decision, start, monthly, cash_rate, fee, lag, signal=True):
    """decision[i] : indice d'actif voulu (ou None) décidé à la clôture de i.
    Exécution à la clôture de i+lag (lag=0 si signal=False)."""
    n = len(dates)
    lag = lag if signal else 0
    cash, shares = 0.0, [0.0] * len(closes_list)
    flows, buys, sells = [], 0, 0
    seen, prev_d, prev_val = set(), None, 0.0
    idx, peak, maxdd = 1.0, 1.0, 0.0
    days, days_inv, total = 0, 0, 0.0
    for i in range(n):
        d = dates[i]
        if d < start:
            continue
        if prev_d is not None and cash > 0:
            cash *= (1 + cash_rate) ** ((d - prev_d).days / 365.0)
        prev_d = d
        pre = cash + sum(s * cl[i] for s, cl in zip(shares, closes_list))
        if prev_val > 0:
            idx *= pre / prev_val
        if month_key(d) not in seen:
            seen.add(month_key(d))
            cash += monthly
            total += monthly
            flows.append((d, -monthly))
        want = decision[i - lag] if i - lag >= 0 else None
        held = next((j for j, s in enumerate(shares) if s > 0), None)
        if held is not None and want != held:
            cash += shares[held] * closes_list[held][i] * (1 - fee)
            shares[held] = 0.0
            sells += 1
            held = None
        if want is not None and cash > 0:
            if held is None:
                buys += 1
            shares[want] += cash * (1 - fee) / closes_list[want][i]
            cash = 0.0
        val = cash + sum(s * cl[i] for s, cl in zip(shares, closes_list))
        prev_val = val
        peak = max(peak, idx)
        maxdd = max(maxdd, 1 - idx / peak)
        days += 1
        days_inv += any(s > 0 for s in shares)
    final = prev_val
    flows.append((dates[-1], final))
    return {"total": total, "final": final, "mult": final / total, "irr": xirr(flows),
            "maxdd": maxdd, "expo": days_inv / days if days else 0.0, "buys": buys, "sells": sells}


def build_decision(name, dates, c, cash_rate):
    if name == "dca":
        return [0] * len(c)
    if name == "trend200":
        s = sig_trend200(dates, c)
    elif name == "cross50":
        s = sig_cross50(dates, c)
    elif name == "faber10m":
        s = sig_faber10m(dates, c)
    elif name == "absmom12":
        s = sig_absmom12(dates, c, cash_rate)
    elif name == "rsi2":
        s = sig_rsi2(dates, c, "ma5")
    elif name == "rsi2b":
        s = sig_rsi2(dates, c, "rsi60")
    elif name == "turtle1":
        s = sig_donchian(dates, c, 20, 10)
    elif name == "turtle2":
        s = sig_donchian(dates, c, 55, 20)
    else:
        raise ValueError(name)
    return [0 if x else None for x in s]


def fmt(label, r):
    return (f"{label:<12}{r['final']:>10,.0f}{r['mult']:>7.2f}{r['irr']:>8.1%}{r['maxdd']:>8.0%}"
            f"{r['expo']:>7.0%}{r['buys']:>8}{r['sells']:>8}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("files", nargs="+")
    p.add_argument("--monthly", type=float, default=500.0)
    p.add_argument("--years", type=int, default=10)
    p.add_argument("--cash-rate", type=float, default=0.03, help="taux annuel du cash (0.03 = 3 %%)")
    p.add_argument("--fee", type=float, default=0.001, help="frais par côté (0.001 = 0,1 %%)")
    p.add_argument("--lag", type=int, default=1, help="jours entre signal et exécution")
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

    print(f"Période : {start} -> {last} | {a.monthly:.0f} €/mois | cash {a.cash_rate:.1%} | frais {a.fee:.2%}/côté | exécution J+{a.lag}")
    print("Colonnes : valeur finale, multiple, TRI, drawdown max (indice hors versements), exposition, achats, ventes\n")
    header = f"{'Stratégie':<12}{'Final':>10}{'Mult.':>7}{'TRI':>8}{'MaxDD':>8}{'Expo':>7}{'Achats':>8}{'Ventes':>8}"
    for f, c in zip(a.files, closes):
        name = f.split("/")[-1].rsplit(".", 1)[0]
        print(f"== {name} (versé {a.monthly * len({(d.year, d.month) for d in dates if d >= start}):,.0f})")
        print(header)
        for s in strategies:
            if s == "dualmom":
                continue
            dec = build_decision(s, dates, c, a.cash_rate)
            print(fmt(s, simulate(dates, [c], dec, start, a.monthly, a.cash_rate, a.fee, a.lag, signal=(s != "dca"))))
        print()
    if "dualmom" in strategies and len(closes) > 1:
        dec = sig_dualmom(dates, closes, a.cash_rate)
        print(f"== PORTEFEUILLE ({', '.join(f.split('/')[-1].rsplit('.', 1)[0] for f in a.files)})")
        print(header)
        print(fmt("dualmom", simulate(dates, closes, dec, start, a.monthly, a.cash_rate, a.fee, a.lag)))


if __name__ == "__main__":
    main()
