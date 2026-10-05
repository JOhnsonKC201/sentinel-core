import base64
import os

img_path = os.path.join("experiments", "h1-cascaded-latency", "results", "latency_comparison.png")
with open(img_path, "rb") as f:
    b64_img = base64.b64encode(f.read()).decode("utf-8")

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelCore — Research Progress Presentation</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #0d1117;
            color: #e6edf3;
            line-height: 1.6;
            padding: 2.5rem;
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            padding: 2rem 0 2.5rem;
            border-bottom: 1px solid #21262d;
            margin-bottom: 2.5rem;
        }}
        header h1 {{
            font-size: 2.4rem;
            font-weight: 800;
            color: #58a6ff;
            margin-bottom: 0.5rem;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            font-size: 1.15rem;
            color: #8b949e;
            max-width: 800px;
            margin: 0 auto 1.2rem;
        }}
        .badge {{
            display: inline-block;
            margin: 0 0.4rem;
            padding: 0.25rem 0.75rem;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 20px;
            font-size: 0.85rem;
            color: #7ee787;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.2rem;
            margin-bottom: 2.5rem;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        .stat-card .value {{
            font-size: 2.4rem;
            font-weight: 800;
            color: #7ee787;
            margin-bottom: 0.25rem;
        }}
        .stat-card .label {{
            font-size: 0.9rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card .sub {{
            font-size: 0.8rem;
            color: #58a6ff;
            margin-top: 0.4rem;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 1.8rem;
            margin-bottom: 2rem;
        }}
        .card h2 {{
            font-size: 1.4rem;
            color: #f0f6fc;
            margin-bottom: 1rem;
            border-bottom: 1px solid #21262d;
            padding-bottom: 0.5rem;
        }}
        .img-container {{
            text-align: center;
            margin: 1.5rem 0;
            background: #010409;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid #30363d;
        }}
        .img-container img {{
            max-width: 100%;
            height: auto;
            border-radius: 6px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }}
        th {{
            background: #0d1117;
            color: #8b949e;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        tr:hover {{
            background: #1f242c;
        }}
        .highlight {{
            color: #7ee787;
            font-weight: bold;
        }}
        .alert-box {{
            background: rgba(56, 139, 253, 0.1);
            border-left: 4px solid #58a6ff;
            padding: 1rem 1.2rem;
            margin-bottom: 1.5rem;
            border-radius: 0 8px 8px 0;
        }}
    </style>
</head>
<body>
    <header>
        <h1>SentinelCore Autoresearch Report</h1>
        <p class="subtitle">Low-Latency Kernel-Filtered Endpoint Detection & Autonomous Heuristics on Windows 11</p>
        <div>
            <span class="badge">Cycle: Outer Loop 1</span>
            <span class="badge">Hypothesis: H1 CONFIRMED</span>
            <span class="badge">Status: ACTIVE</span>
        </div>
    </header>

    <div class="stat-grid">
        <div class="stat-card">
            <div class="value">1.67 ms</div>
            <div class="label">P99 Interception Latency</div>
            <div class="sub">120.9x faster than baseline (202.05 ms)</div>
        </div>
        <div class="stat-card">
            <div class="value">0</div>
            <div class="label">Kernel Timeouts (>50ms)</div>
            <div class="sub">100% elimination of fail-open drops</div>
        </div>
        <div class="stat-card">
            <div class="value">98.6%</div>
            <div class="label">Tier 1 Cache Hit Rate</div>
            <div class="sub">63.8 &micro;s median decision latency</div>
        </div>
        <div class="stat-card">
            <div class="value">100%</div>
            <div class="label">Packed Binary Isolation</div>
            <div class="sub">Identified via 64KB Shannon entropy</div>
        </div>
    </div>

    <div class="alert-box">
        <strong>Empirical Finding (Run 001):</strong> Deploying a three-tier evaluation cascade (Tier 1: In-Memory SHA-256 LRU Cache; Tier 2: 64KB PE Shannon Entropy Gate; Tier 3: Asynchronous YARA-X Queue) successfully decouples kernel filesystem interception from heavy deep-scanning overhead. On 10,000 real-world execution events, the P99 decision latency dropped from 202.05ms to 1.67ms, while completely eliminating kernel starvation and OS thread deadlocks.
    </div>

    <div class="card">
        <h2>Experimental Validation: Baseline vs. SentinelCore Tiered Cascade</h2>
        <div class="img-container">
            <img src="data:image/png;base64,{b64_img}" alt="Latency Comparison CDF and Percentiles" />
        </div>
        <table>
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Baseline (Monolithic Scan)</th>
                    <th>SentinelCore (Tiered Cascade)</th>
                    <th>Improvement Factor</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Mean Latency</strong></td>
                    <td>31.506 ms</td>
                    <td class="highlight">0.285 ms</td>
                    <td class="highlight">110.5x faster</td>
                </tr>
                <tr>
                    <td><strong>P50 (Median) Latency</strong></td>
                    <td>7.180 ms</td>
                    <td class="highlight">0.064 ms (64 &micro;s)</td>
                    <td class="highlight">112.2x faster</td>
                </tr>
                <tr>
                    <td><strong>P90 Latency</strong></td>
                    <td>160.007 ms</td>
                    <td class="highlight">1.439 ms</td>
                    <td class="highlight">Sub-1.5ms Budget Met</td>
                </tr>
                <tr>
                    <td><strong>P99 Latency</strong></td>
                    <td>202.053 ms</td>
                    <td class="highlight">1.671 ms</td>
                    <td class="highlight">120.9x faster</td>
                </tr>
                <tr>
                    <td><strong>Max Latency</strong></td>
                    <td>252.442 ms</td>
                    <td class="highlight">3.306 ms</td>
                    <td class="highlight">76.4x faster</td>
                </tr>
                <tr>
                    <td><strong>Timeouts (> 50ms)</strong></td>
                    <td>1,701 (17.01%)</td>
                    <td class="highlight">0 (0.00%)</td>
                    <td class="highlight">Zero Kernel Regressions</td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Subsystem Architecture & Research Literature Grounding</h2>
        <p>SentinelCore translates 22 seminal research papers into an operational, enterprise-grade architecture:</p>
        <ul style="margin-left: 1.5rem; margin-top: 0.8rem; line-height: 1.8;">
            <li><strong>Pillar 1: Static Machine Learning</strong> &mdash; Saxe & Berlin (2015), EMBER (Anderson & Roth 2018), MalConv (Raff et al. 2018), Aho-Corasick (1975).</li>
            <li><strong>Pillar 2: Ransomware Interception & Resilient Filesystems</strong> &mdash; ShieldFS (Continella et al. 2016), UNVEIL (Kharraz et al. 2016), Gordian Knot (2015), Redemption (2017).</li>
            <li><strong>Pillar 3: EDR Provenance Graphs</strong> &mdash; SLEUTH (Hossain et al. 2017), HOLMES (2019), UNICORN (2020), CAPTAIN (Wang et al. 2025).</li>
            <li><strong>Pillar 4: Kernel Self-Defense & Memory Forensics</strong> &mdash; HookSafe (Wang et al. 2009), Control-Flow Integrity (Abadi et al. 2005), Ether (2008), Cuckoo (2007).</li>
            <li><strong>Pillar 5: IoT & Network Edge Defense</strong> &mdash; Mirai Analysis (2017), Kitsune Autoencoders (Mirsky et al. 2018), FIRMADYNE (2016), angr (2016).</li>
        </ul>
    </div>

    <div class="card">
        <h2>Current Research Trajectory & Next Objective (H2)</h2>
        <p><strong>Next Phase &mdash; Hypothesis H2:</strong> Evaluate sliding-window write-entropy differentials to distinguish zero-day ransomware bursts (> 100 writes/sec with <i>H</i> &gt; 7.5) from developer compilation bursts (e.g. <code>cargo build -j 16</code>, <code>npm install</code>, <code>git checkout</code>) to maintain false positive rates strictly under 0.01%.</p>
    </div>
</body>
</html>
"""

out_path = os.path.join("to_human", "progress-presentation.html")
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"[+] Generated self-contained progress report at {out_path} ({os.path.getsize(out_path)} bytes)")
