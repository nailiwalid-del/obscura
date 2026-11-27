import re, subprocess, sys, statistics as st
tag, extra = sys.argv[1], sys.argv[2:]
syms = ["XLB","XLE","XLF","XLI","XLK","XLP","XLU","XLV","XLY"]
files = [f"data/panier/{s}_{tag}.csv" for s in syms]
strats = "dca,trend200,k_pull2,k_pull2_tms,k_pull2_ts,k_atr_tms,k_atr_ts"
out = subprocess.run(["python3","-I","backtest_v10.py",*files,"--strategies",strats,*extra],capture_output=True,text=True).stdout
rows, cur = {}, None
for l in out.splitlines():
    m = re.match(r"== (\w+)", l)
    if m: cur = m.group(1); continue
    m = re.match(r"(\w+)\s+([\d,]+)\s+([\d.]+)\s+(-?[\d.]+|nan)%\s+(\d+)%\s+(\d+)%\s+(\d+)\s+(\d+)", l)
    if m and cur:
        rows.setdefault(m.group(1), {})[cur] = (float(m.group(4)) if m.group(4)!="nan" else float("nan"), int(m.group(5)), int(m.group(6)), int(m.group(7)))
dca = rows["dca"]
print(out.splitlines()[0])
print(f"{'Stratégie':<12}{'TRI moy':>9}{'TRI méd':>9}{'MaxDD moy':>11}{'Expo moy':>10}{'Trans.':>8}{'>DCA':>7}")
for s, d in rows.items():
    tri = [v[0] for v in d.values()]
    beat = sum(1 for k, v in d.items() if v[0] > dca[k][0])
    print(f"{s:<12}{st.mean(tri):>8.1f}%{st.median(tri):>8.1f}%{st.mean(v[1] for v in d.values()):>10.0f}%{st.mean(v[2] for v in d.values()):>9.0f}%{st.mean(v[3] for v in d.values()):>8.0f}{beat:>5}/9")
print("TRI par ETF (dca | k_pull2 | k_atr_tms):", ", ".join(f"{k} {dca[k][0]:.1f}|{rows['k_pull2'][k][0]:.1f}|{rows['k_atr_tms'][k][0]:.1f}" for k in dca))
