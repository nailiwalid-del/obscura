"""
Backtest v10 (v9 + stops basés sur l'ATR(14) de Wilder ; lit des fichiers data/ohlc/*.csv : Date,High,Low,Close).
  k_atr_tms  Entrée de k_pull2 ; sortie si Close < MM tendance OU Close <= plus haut depuis l'entrée - --atr-mult x ATR (stop suiveur, défaut 3).
  k_atr_ts   Idem, stop suiveur ATR seul.
  k_atr_fs   Stop FIXE à --atr-fixed x ATR(entrée) sous le prix d'entrée (défaut 2 : style Turtle), seul.
  Les multiples 3 et 2 sont des valeurs courantes de la littérature, pas des règles de l'auteur.
Backtest v9 (v8 + stop SUIVEUR : k_pull2_tms = MM100 OU stop suiveur, k_pull2_ts = stop suiveur seul ; --kstop, défaut 8 %, choix de l'outil).
Backtest v8 (v7 + sorties de k_pull2 avec stop : k_pull2_ms = MM100 OU stop, k_pull2_s = stop seul ; --kstop, défaut 8 %, choix de l'outil).
Backtest v7 (v6 + k_pull2 : règles tirées de la conférence YouTube pbCkiaAG3vc et du court extrait ixnFWPZy6-s, voir regles_kabbaj.md).
Backtest v6 (v5 + stratégie k_pull issue de la vidéo YouTube e6HGgUc0lYk, voir regles_kabbaj.md).
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
  k_pull     Repli sur la zone des 50 du RSI dans une tendance haussière (vidéo YouTube) :
             tendance = Close > MM200 (choix de l'outil) ; le RSI(n) touche <= 50 -> armé ;
             entrée quand le RSI repasse > 50 (confirmation, choix de l'outil) ; sortie si
             Close < MM200 (choix de l'outil). Aucun stop ni taille de position (non cités).
  k_pull2    Version « conférence » : tendance = Close > moyenne mobile arithmétique de --trend-ma
             jours (100 par défaut ; il cite 100 ou 150 pour le long terme) ; repli du RSI(n) sur la
             zone 50 puis rebond > 50 ; entrée à --init-weight (50 %) puis renfort à 100 % quand
             Close > MM20 > MM50 (« taille initiale, puis renforcer ») ; sortie si Close < MM tendance.
             Pas de stop ni de taille chiffrée (non cités). Divergences RSI, stochastique, volumes
             et « bougie de contrôle » NON codés (non définis dans les extraits).
"""
import argparse
import csv
from datetime import date, timedelta

ALL = ["dca", "trend200", "rsi50", "k_stop", "k_risk", "k_pull", "k_pull2", "k_pull2_ms", "k_pull2_s", "k_pull2_tms", "k_pull2_ts", "k_atr_tms", "k_atr_ts", "k_atr_fs"]


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


def load_ohlc(path):
    out = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                out[date.fromisoformat(r["Date"][:10])] = (float(r["High"]), float(r["Low"]), float(r["Close"]))
            except (KeyError, ValueError):
                continue
    return out


def atr_wilder(highs, lows, closes, n=14):
    tr = [highs[0] - lows[0]] + [max(highs[i] - lows[i], abs(highs[i] - closes[i - 1]), abs(lows[i] - closes[i - 1]))
                                for i in range(1, len(closes))]
    out = [None] * len(closes)
    if len(closes) < n:
        return out
    a = sum(tr[:n]) / n
    out[n - 1] = a
    for i in range(n, len(closes)):
        a = (a * (n - 1) + tr[i]) / n
        out[i] = a
    return out


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


def w_pullback(dates, c, n):
    r, ma = rsi(c, n), sma(c, 200)
    out, hold, armed = [], False, False
    for i in range(len(c)):
        if r[i] is None or ma[i] is None:
            out.append(0.0)
            continue
        trend = c[i] > ma[i]
        if hold:
            if not trend:
                hold, armed = False, False
        else:
            if trend and r[i] <= 50:
                armed = True
            if not trend:
                armed = False
            if armed and trend and r[i] > 50:
                hold, armed = True, False
        out.append(1.0 if hold else 0.0)
    return out


def w_pullback2(dates, c, n, trend_n, init_w, stop=None, mode="ma", trailing=False):
    """mode : 'ma' sortie Close < MM tendance ; 'ma+stop' MM ou stop ; 'stop' stop seul.
    Le stop est fixe, sous le prix d'entrée (clôtures). Après un stop, ré-armement requis
    (le RSI doit retoucher <= 50 en tendance)."""
    r, tma, m20, m50 = rsi(c, n), sma(c, trend_n), sma(c, 20), sma(c, 50)
    out, hold, armed, scaled, entry, peak = [], False, False, False, 0.0, 0.0
    for i in range(len(c)):
        if r[i] is None or tma[i] is None or m50[i] is None:
            out.append(0.0)
            continue
        trend = c[i] > tma[i]
        if hold:
            peak = max(peak, c[i])
            ref = peak if trailing else entry
            stopped = stop is not None and mode != "ma" and c[i] <= ref * (1 - stop)
            trend_exit = mode != "stop" and not trend
            if stopped or trend_exit:
                hold = scaled = False
                armed = False
            elif not scaled and c[i] > m20[i] > m50[i]:
                scaled = True
        else:
            if (trend or mode == "stop") and r[i] <= 50:
                armed = True
            if mode != "stop" and not trend:
                armed = False
            if armed and (trend or mode == "stop") and r[i] > 50:
                hold, armed, entry, peak = True, False, c[i], c[i]
                scaled = bool(c[i] > m20[i] > m50[i])
        out.append((1.0 if scaled else init_w) if hold else 0.0)
    return out


def w_pullback_atr(dates, c, atr, n, trend_n, init_w, mode, mult):
    """Entrée identique à k_pull2. mode : 'tms' (MM ou stop suiveur), 'ts' (stop suiveur seul),
    'fs' (stop fixe seul = entrée - mult x ATR à l'entrée). Ré-armement du RSI requis après un stop."""
    r, tma, m20, m50 = rsi(c, n), sma(c, trend_n), sma(c, 20), sma(c, 50)
    out, hold, armed, scaled, peak, fixed = [], False, False, False, 0.0, 0.0
    for i in range(len(c)):
        if r[i] is None or tma[i] is None or m50[i] is None or atr[i] is None:
            out.append(0.0)
            continue
        trend = c[i] > tma[i]
        free = mode != "tms"
        if hold:
            peak = max(peak, c[i])
            if mode == "fs":
                stopped = c[i] <= fixed
            else:
                stopped = c[i] <= peak - mult * atr[i]
            if stopped or (mode == "tms" and not trend):
                hold = scaled = armed = False
            elif not scaled and c[i] > m20[i] > m50[i]:
                scaled = True
        else:
            if (trend or free) and r[i] <= 50:
                armed = True
            if not free and not trend:
                armed = False
            if armed and (trend or free) and r[i] > 50:
                hold, armed, peak = True, False, c[i]
                fixed = c[i] - mult * atr[i]
                scaled = bool(c[i] > m20[i] > m50[i])
        out.append((1.0 if scaled else init_w) if hold else 0.0)
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
    p.add_argument("--trend-ma", type=int, default=100, help="MM de tendance de k_pull2 (100 ou 150 cités)")
    p.add_argument("--init-weight", type=float, default=0.5, help="poids initial de k_pull2 avant renfort")
    p.add_argument("--kstop", type=float, default=0.08, help="stop de k_pull2_ms / k_pull2_s (0.08 = 8 %%)")
    p.add_argument("--atr-mult", type=float, default=3.0, help="multiple d'ATR du stop suiveur")
    p.add_argument("--atr-fixed", type=float, default=2.0, help="multiple d'ATR du stop fixe (style Turtle)")
    p.add_argument("--end", default=None, help="dernière date AAAA-MM-JJ (comparabilité)")
    p.add_argument("--strategies", default=",".join(ALL))
    a = p.parse_args()
    strategies = [s.strip() for s in a.strategies.split(",") if s.strip()]
    for s in strategies:
        if s not in ALL:
            p.error(f"stratégie inconnue : {s} (choix : {', '.join(ALL)})")

    data = [load_ohlc(f) for f in a.files]
    dates = sorted(set.intersection(*[set(d) for d in data]))
    if a.end:
        dates = [d for d in dates if d <= date.fromisoformat(a.end)]
    closes = [[d[x][2] for x in dates] for d in data]
    atrs = [atr_wilder([d[x][0] for x in dates], [d[x][1] for x in dates], cl, 14) for d, cl in zip(data, closes)]
    last = dates[-1]
    start = date(last.year - a.years, last.month, last.day) + timedelta(days=1)
    wk = min(1.0, a.risk / a.stop)

    print(f"Période : {start} -> {last} | {a.monthly:.0f} €/mois | cash {a.cash_rate:.1%} | frais {a.fee:.2%}/côté | exécution J+{a.lag}")
    print(f"Paramètres choisis par l'outil (pas par l'auteur) : RSI({a.rsi_n}), stop {a.stop:.0%}, risque {a.risk:.0%} -> poids k_risk {wk:.0%}")
    print("Colonnes : valeur finale, multiple, TRI, drawdown max, exposition moyenne, achats, ventes\n")
    header = f"{'Stratégie':<12}{'Final':>10}{'Mult.':>7}{'TRI':>8}{'MaxDD':>8}{'Expo':>7}{'Achats':>8}{'Ventes':>8}"
    for f, c, atr in zip(a.files, closes, atrs):
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
            elif s == "k_pull2":
                w = w_pullback2(dates, c, a.rsi_n, a.trend_ma, a.init_weight)
            elif s == "k_pull2_ms":
                w = w_pullback2(dates, c, a.rsi_n, a.trend_ma, a.init_weight, a.kstop, "ma+stop")
            elif s == "k_atr_tms":
                w = w_pullback_atr(dates, c, atr, a.rsi_n, a.trend_ma, a.init_weight, "tms", a.atr_mult)
            elif s == "k_atr_ts":
                w = w_pullback_atr(dates, c, atr, a.rsi_n, a.trend_ma, a.init_weight, "ts", a.atr_mult)
            elif s == "k_atr_fs":
                w = w_pullback_atr(dates, c, atr, a.rsi_n, a.trend_ma, a.init_weight, "fs", a.atr_fixed)
            elif s == "k_pull2_tms":
                w = w_pullback2(dates, c, a.rsi_n, a.trend_ma, a.init_weight, a.kstop, "ma+stop", True)
            elif s == "k_pull2_ts":
                w = w_pullback2(dates, c, a.rsi_n, a.trend_ma, a.init_weight, a.kstop, "stop", True)
            elif s == "k_pull2_s":
                w = w_pullback2(dates, c, a.rsi_n, a.trend_ma, a.init_weight, a.kstop, "stop")
            elif s == "k_pull":
                w = w_pullback(dates, c, a.rsi_n)
            elif s == "k_stop":
                w = w_kabbaj(dates, c, a.rsi_n, a.stop, 1.0)
            else:
                w = w_kabbaj(dates, c, a.rsi_n, a.stop, wk)
            print(fmt(s, simulate(dates, c, w, start, a.monthly, a.cash_rate, a.fee, a.lag, signal=(s != "dca"))))
        print()


if __name__ == "__main__":
    main()
