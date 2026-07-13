#!/usr/bin/env python3
"""
iris_analyst_report.py — Relatório de produtividade por analista no DFIR IRIS
Compatível com: IRIS v2.4.26 | API v2.0.4 / v2.0.5

Correções aplicadas:
  - Força busca de detalhes quando há múltiplos analistas (evita histórico truncado)
  - Separação clara entre MTTA (primeira ação) e MTTR (resolução)
  - Parser de datas ultra-robusto (aceita DD/MM/YYYY, ISO, etc)
  - Multi-analista: cada alerta aparece para TODOS que atuaram nele
  - Proteção anti-loop e pausas adaptativas
  - 🆕 Sinal 4: Busca detalhes quando alerta está FECHADO mas histórico não mostra fechamento
  - 🆕 Sinal 5: Busca detalhes quando tem resolução mas sem evento correspondente
"""

import os, json, re, argparse, sys, csv, time
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import requests, urllib3

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    load_dotenv() # Carrega as variáveis do arquivo .env automaticamente
except ImportError:
    pass # Se não tiver a biblioteca, usa as variáveis do sistema ou os fallbacks

IRIS_URL   = os.environ.get("IRIS_URL",   "http://localhost")
IRIS_TOKEN = os.environ.get("IRIS_TOKEN", "") # <--- Deixado em branco por segurança


SYSTEM_USERS = {"fast", "globaltech", "system", "iris", "wazuh", "yamaha"}

SEV_MAP   = {1:"informational", 2:"low", 3:"medium", 4:"high", 5:"critical"}
SEV_ORDER = ["critical","high","medium","low","informational","unknown"]
SEV_ICON  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢",
              "informational":"⚪","unknown":"⚫"}

RESOLUTION_MAP = {
    1: "False Positive",
    2: "Not Applicable",
    3: "True Positive With Impact",
    4: "True Positive Without Impact",
    5: "Legitimate",
    6: "Unknown",
}

BRT_OFFSET = timedelta(hours=-3)

def parse_dt(v):
    """Parser de datas ultra-robusto."""
    if not v: return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    v_clean = str(v).strip().strip('"').strip("'")
    if not v_clean: return None
    
    formats = (
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M", "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
        "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%d-%m-%Y",
    )
    
    for fmt in formats:
        try:
            max_len = 26 if "%f" in fmt else len(v_clean)
            return datetime.strptime(v_clean[:max_len], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    
    m = re.match(r'(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?', v_clean)
    if m:
        day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hour = int(m.group(4) or 0)
        minute = int(m.group(5) or 0)
        second = int(m.group(6) or 0)
        try:
            return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            pass
    return None

def fmt_h(h):
    if h is None: return "N/A"
    if h < 0: return "N/A"
    if h < 0.017: return "< 1 min"
    if h < 1: return f"{h*60:.0f} min"
    if h < 24: return f"{h:.1f} h"
    return f"{h/24:.1f} dias"

def avg(lst): return sum(lst)/len(lst) if lst else None

def to_brt(dt_or_str):
    if not dt_or_str: return ""
    dt = dt_or_str if isinstance(dt_or_str, datetime) else parse_dt(dt_or_str)
    if dt is None: return ""
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return (dt + BRT_OFFSET).strftime("%Y-%m-%dT%H:%M:%S")

def normalize_user(name):
    if not name: return ""
    return str(name).strip()

def users_match(a, b):
    if not a or not b: return False
    a, b = a.lower().strip(), b.lower().strip()
    if a == b: return True
    a_base = a.split("@")[0] if "@" in a else a
    b_base = b.split("@")[0] if "@" in b else b
    return a_base == b_base

def resolve_period(args):
    def parse_user_date(s):
        for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y"):
            try: return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError: pass
        raise ValueError(f"Data inválida: '{s}'. Use DD/MM/YYYY")
    now = datetime.now(tz=timezone.utc)
    if getattr(args, "date", None):
        d = parse_user_date(args.date)
        return d, d.replace(hour=23, minute=59, second=59, microsecond=999999), \
               f"{d.strftime('%d/%m/%Y')} (dia inteiro)"
    if getattr(args, "date_from", None) or getattr(args, "date_to", None):
        df = parse_user_date(args.date_from) if getattr(args,"date_from",None) else now-timedelta(days=30)
        dt = parse_user_date(args.date_to)   if getattr(args,"date_to",  None) else now
        if df > dt:
            print("  AVISO: período invertido — corrigido automaticamente")
            df, dt = dt, df
        return df, dt.replace(hour=23, minute=59, second=59, microsecond=999999), \
               f"{df.strftime('%d/%m/%Y')} → {dt.strftime('%d/%m/%Y')}"
    days = getattr(args, "days", 30) or 30
    return now - timedelta(days=days), now, f"últimos {days} dias"

def parse_mod_history(mh):
    if not mh or not isinstance(mh, dict): return []
    events = []
    for ts_key, info in mh.items():
        if not isinstance(info, dict): continue
        try:
            ts = datetime.fromtimestamp(float(ts_key), tz=timezone.utc)
        except (ValueError, OSError): continue
        events.append({
            "ts": ts,
            "user": normalize_user(info.get("user", "")),
            "action": str(info.get("action", "")).strip(),
        })
    events.sort(key=lambda x: x["ts"])
    return events

def first_analyst_event(events):
    for e in events:
        if e["user"].lower() in SYSTEM_USERS: continue
        if e["action"].lower() in ("alert created", "case created", "created"): continue
        return e
    return None

def all_analysts_in_history(events):
    return {normalize_user(e["user"]) for e in events
            if e["user"].lower() not in SYSTEM_USERS
            and e["action"].lower() not in ("alert created", "case created", "created")}

def categorize_action(action_str):
    if not action_str: return "—"
    a = action_str.lower()
    if "merged into" in a: return "Vinculado a case"
    if "unmerged" in a: return "Desvinculado de case"
    if "escalat" in a: return "Escalado"
    if "alert_status_id" in a: return "Status alterado"
    if "alert_note" in a: return "Nota adicionada"
    if "alert_resolution" in a: return "Resolução definida"
    if "closed" in a: return "Fechado"
    if "owner" in a: return "Atribuído"
    return action_str[:35]

def alert_resolution_status(alert_details, alert_obj):
    sources = []
    if isinstance(alert_details, dict):
        sources.append(alert_details)
        if isinstance(alert_details.get("alert"), dict):
            sources.append(alert_details["alert"])
    if isinstance(alert_obj, dict):
        sources.append(alert_obj)

    for src in sources:
        res = src.get("resolution_status")
        if isinstance(res, dict):
            name = (res.get("resolution_status_name") or res.get("status_name")
                    or res.get("name") or res.get("value"))
            if name: return str(name).strip()

    for src in sources:
        rid = (src.get("alert_resolution_status_id") or src.get("resolution_status_id"))
        if rid is not None:
            try: return RESOLUTION_MAP.get(int(rid), f"ID_{rid}")
            except: return f"ID_{rid}"

    events = parse_mod_history(alert_obj.get("modification_history", {}))
    for e in reversed(events):
        if "alert_resolution_status_id" in e["action"]:
            return "alterado manualmente"
    return "Não classificado"

def alert_status_name(a):
    s = a.get("status")
    if isinstance(s, dict): return s.get("status_name","unknown")
    return "unknown"

class IrisClient:
    def __init__(self, base_url, token, verify_ssl=False):
        self.base = base_url.rstrip("/")
        self._token = token
        self.verify = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        })

    def _get(self, path, params=None, retries=5, backoff=3):
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                r = self.session.get(f"{self.base}{path}", params=params,
                                     verify=self.verify, timeout=60)
                r.raise_for_status()
                d = r.json()
                return d.get("data", d) if isinstance(d, dict) else d
            except Exception as e:
                last_err = e
                wait = backoff * attempt
                sys.stderr.write(f"\n  [RETRY {attempt}/{retries}] {type(e).__name__} — {wait}s\n")
                sys.stderr.flush()
                time.sleep(wait)
                self.session = requests.Session()
                self.session.headers.update({
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json"
                })
        raise last_err

    def fetch_alerts(self, date_from, date_to, max_pages=500, analyst_filter=None):
        items, page = [], 1
        params = {"per_page": 200}
        if date_from:
            params["creation_date_from"] = date_from.strftime("%Y-%m-%dT00:00:00")
            params["date_from"] = date_from.strftime("%Y-%m-%d")
        if date_to:
            params["creation_date_to"] = date_to.strftime("%Y-%m-%dT23:59:59")
            params["date_to"] = date_to.strftime("%Y-%m-%d")
        if analyst_filter:
            params["alert_owner"] = analyst_filter

        empty_pages_count = 0
        MAX_EMPTY_PAGES = 10

        while page <= max_pages:
            params["page"] = page
            result = self._get("/alerts/filter", params)
            batch = result.get("alerts", []) if isinstance(result, dict) else result
            if not batch: break

            page_had_match = False
            for a in batch:
                dt = parse_dt(a.get("alert_creation_time"))
                if dt is None:
                    items.append(a); continue
                if date_to and dt > date_to: continue
                if dt >= date_from:
                    items.append(a)
                    page_had_match = True

            last_page = result.get("last_page", 1) if isinstance(result, dict) else 1

            if not page_had_match and len(items) > 0:
                empty_pages_count += 1
                if empty_pages_count >= MAX_EMPTY_PAGES:
                    sys.stderr.write(f"\n  [ALERTAS] ⚠️ Parando ({MAX_EMPTY_PAGES} páginas sem dados)\n")
                    sys.stderr.flush()
                    break
            else:
                empty_pages_count = 0

            sys.stderr.write(f"\r  Pág {page}/{min(last_page, max_pages)} | {len(items)} alertas   ")
            sys.stderr.flush()

            if page >= last_page or page >= max_pages: break
            page += 1
            if page % 50 == 0:
                sys.stderr.write(f"\n  [pausa] {page} páginas — aguardando 2s...\n")
                sys.stderr.flush()
                time.sleep(2)

        sys.stderr.write("\n")
        return items

    def fetch_alert_details(self, alert_id):
        try:
            return self._get(f"/alerts/{alert_id}")
        except Exception as e:
            sys.stderr.write(f"  [AVISO] Falha detalhes {alert_id}: {e}\n")
            sys.stderr.flush()
            return None

    def fetch_cases(self, date_from, date_to, max_pages=500):
        items, page = [], 1
        params = {"per_page": 100}
        if date_from:
            params["open_date_from"] = date_from.strftime("%Y-%m-%dT00:00:00")
            params["creation_date_from"] = date_from.strftime("%Y-%m-%d")
        if date_to:
            params["open_date_to"] = date_to.strftime("%Y-%m-%dT23:59:59")
            params["creation_date_to"] = date_to.strftime("%Y-%m-%d")

        empty_pages_count = 0
        MAX_EMPTY_PAGES = 10

        while page <= max_pages:
            params["page"] = page
            result = self._get("/manage/cases/filter", params)
            batch = result.get("cases", []) if isinstance(result, dict) else result
            if not batch: break

            page_had_match = False
            for c in batch:
                dt = parse_dt(c.get("initial_date") or c.get("open_date"))
                if dt is None:
                    items.append(c); continue
                if date_to and dt > date_to: continue
                if dt >= date_from:
                    items.append(c)
                    page_had_match = True

            last_page = result.get("last_page", 1) if isinstance(result, dict) else 1

            if not page_had_match and len(items) > 0:
                empty_pages_count += 1
                if empty_pages_count >= MAX_EMPTY_PAGES:
                    sys.stderr.write(f"\n  [CASES] ⚠️ Parando ({MAX_EMPTY_PAGES} páginas sem dados)\n")
                    sys.stderr.flush()
                    break
            else:
                empty_pages_count = 0

            sys.stderr.write(f"\r  Pág {page}/{min(last_page, max_pages)} | {len(items)} cases   ")
            sys.stderr.flush()

            if page >= last_page or page >= max_pages: break
            page += 1
            if page % 20 == 0:
                sys.stderr.write(f"\n  [pausa] {page} páginas — aguardando 1s...\n")
                sys.stderr.flush()
                time.sleep(1)

        sys.stderr.write("\n")
        return items

def alert_sev(a):
    s = a.get("severity")
    if isinstance(s, dict): return s.get("severity_name","unknown").lower()
    sid = a.get("alert_severity_id")
    return SEV_MAP.get(int(sid),"unknown") if sid else "unknown"

def case_sev(c):
    sid = c.get("severity_id")
    if sid: return SEV_MAP.get(int(sid),"unknown")
    s = c.get("severity")
    return s.get("severity_name","unknown").lower() if isinstance(s,dict) else "unknown"

def is_closed(c):
    s = c.get("state_id")
    if s is not None: return int(s) == 9
    st = c.get("state") or {}
    return "closed" in st.get("state_name","").lower() if isinstance(st,dict) else False

def analyze(alerts, cases, analyst_filter=None, debug=False, fetch_resolution=False, client=None):
    data = defaultdict(lambda: {
        "alerts": [], "cases_open": [], "cases_closed": [], "mttr_samples": [],
        "alert_sev": defaultdict(int), "alert_status": defaultdict(int),
        "alert_resolution": defaultdict(int), "alert_action_types": defaultdict(int),
        "case_sev": defaultdict(int),
        "alert_response_times": [], "case_response_times": [], "history_actions": [],
    })

    debug_done = False
    alert_details_cache = {}
    total_alerts = len(alerts)
    use_details_forced = fetch_resolution and client is not None

    for idx, a in enumerate(alerts):
        created_raw = parse_dt(a.get("alert_creation_time"))
        mh = a.get("modification_history", {})
        events = parse_mod_history(mh)

        created_event = next(
            (e for e in events if e["action"].lower() in ("alert created", "created")), None
        )
        created = created_event["ts"] if created_event else created_raw

        if debug and not debug_done:
            print("\n[DEBUG] Timestamps do 1º alerta:")
            print(f"  alert_creation_time (API) : {created_raw}")
            print(f"  Alert created (histórico) : {created_event['ts'] if created_event else 'N/A'}")
            print(f"  Usando para MTTA          : {created}")
            debug_done = True

        acting_analysts = all_analysts_in_history(events)

        if not acting_analysts:
            owner = a.get("owner")
            if isinstance(owner, dict):
                name = owner.get("user_login") or owner.get("user_name")
                if name and name.lower() not in SYSTEM_USERS:
                    acting_analysts = {normalize_user(name)}

        if not acting_analysts:
            continue

        # 🔧 CORREÇÃO CRÍTICA: Força busca de detalhes em casos estratégicos
        needs_detailed_fetch = False
        owner_obj = a.get("owner") or {}
        current_owner = normalize_user(
            owner_obj.get("user_login") or owner_obj.get("user_name") or ""
        )
        first_action = first_analyst_event(events)
        first_by = normalize_user(first_action["user"]) if first_action else ""
        current_status = alert_status_name(a)
        
        # Sinal 1: Múltiplos analistas atuaram
        if len(acting_analysts) > 1:
            needs_detailed_fetch = True
            if debug:
                print(f"  [SMART] Alerta #{a.get('alert_id')}: {len(acting_analysts)} analistas detectados, "
                      f"buscando histórico completo...")
        
        # Sinal 2: Hand-off detectado
        if current_owner and first_by and not users_match(current_owner, first_by):
            needs_detailed_fetch = True
            if debug:
                print(f"  [SMART] Alerta #{a.get('alert_id')}: hand-off detectado "
                      f"({first_by} → {current_owner}), buscando detalhes...")
        
        # Sinal 3: Owner não está entre os analistas do histórico
        if current_owner and not any(users_match(current_owner, u) for u in acting_analysts):
            needs_detailed_fetch = True
            if debug:
                print(f"  [SMART] Alerta #{a.get('alert_id')}: owner {current_owner} "
                      f"não está no histórico, buscando detalhes...")
        
        # 🆕 Sinal 4: Alerta FECHADO mas sem evento de fechamento no histórico
        # Captura casos onde a API truncou o histórico omitindo o fechamento
        if current_status.lower() == "closed":
            has_close_event = any(
                "closed" in e["action"].lower() or 
                "resolution_status_id" in e["action"]
                for e in events
            )
            if not has_close_event:
                needs_detailed_fetch = True
                if debug:
                    print(f"  [SMART] Alerta #{a.get('alert_id')}: status=Closed mas sem evento de "
                          f"fechamento no histórico (truncado), buscando detalhes...")
        
        # 🆕 Sinal 5: Alerta tem resolução mas sem evento correspondente
        res_status = alert_resolution_status(None, a)
        if res_status and res_status != "Não classificado":
            has_resolution_event = any(
                "resolution" in e["action"].lower() for e in events
            )
            if not has_resolution_event:
                needs_detailed_fetch = True
                if debug:
                    print(f"  [SMART] Alerta #{a.get('alert_id')}: resolução '{res_status}' "
                          f"sem evento no histórico")

        alert_details = None
        if client and (use_details_forced or needs_detailed_fetch):
            alert_id = a.get("alert_id")
            if alert_id not in alert_details_cache:
                sys.stderr.write(f"  [DETALHES] Buscando {idx+1}/{total_alerts}\n")
                sys.stderr.flush()
                alert_details_cache[alert_id] = client.fetch_alert_details(alert_id)
                time.sleep(0.05)
            alert_details = alert_details_cache.get(alert_id)
            
            if alert_details:
                alert_obj = alert_details.get("alert", alert_details)
                mh_full = alert_obj.get("modification_history", {})
                events = parse_mod_history(mh_full)
                
                acting_analysts = all_analysts_in_history(events)
                if not acting_analysts:
                    if current_owner:
                        acting_analysts = {current_owner}
                first_action = first_analyst_event(events)
                first_by = normalize_user(first_action["user"]) if first_action else ""

        if not acting_analysts:
            continue

        if analyst_filter:
            acting_analysts = {u for u in acting_analysts if users_match(u, analyst_filter)}
            if not acting_analysts:
                continue

        atype = categorize_action(first_action["action"] if first_action else "")
        res_status = alert_resolution_status(alert_details, a)
        atual_owner = current_owner

        # 🔧 Detecta evento de fechamento para calcular MTTR
        close_event = next(
            (e for e in reversed(events) if "closed" in e["action"].lower() or 
             "resolution_status_id" in e["action"]), None
        )

        history_logged = False
        for analyst in acting_analysts:
            d = data[analyst]

            # MTTA: tempo até PRIMEIRA ação humana
            resp_h = None
            if first_action and created and users_match(first_action["user"], analyst):
                resp_h = (first_action["ts"] - created).total_seconds() / 3600
                if 0 <= resp_h < 720:
                    d["alert_response_times"].append(resp_h)

            # 🔧 MTTR: tempo até RESOLUÇÃO (só para quem fechou)
            mttr_h = None
            if close_event and created and users_match(close_event["user"], analyst):
                mttr_h = (close_event["ts"] - created).total_seconds() / 3600
                if 0 <= mttr_h < 720:
                    d["mttr_samples"].append(mttr_h)

            if not history_logged:
                for e in events:
                    if e["user"].lower() not in SYSTEM_USERS and \
                       e["action"].lower() not in ("alert created", "case created", "created"):
                        d["history_actions"].append({
                            "tipo": "alerta", "id": a.get("alert_id"),
                            "ts": (e["ts"] + BRT_OFFSET).strftime("%d/%m/%Y %H:%M"),
                            "user": e["user"], "action": e["action"],
                        })
                history_logged = True

            d["alerts"].append({
                "alert_id": a.get("alert_id"),
                "title": a.get("alert_title","")[:80],
                "severity": alert_sev(a),
                "status": alert_status_name(a),
                "resolution": res_status,
                "action_type": atype,
                "customer": (a.get("customer") or {}).get("customer_name","?"),
                "created": to_brt(created_raw),
                "available": to_brt(created) if created else "",
                "tags": a.get("alert_tags",""),
                "resp_h": round(resp_h, 2) if resp_h is not None else None,
                "resp_fmt": fmt_h(resp_h),
                "mttr_h": round(mttr_h, 2) if mttr_h is not None else None,
                "mttr_fmt": fmt_h(mttr_h),
                "first_action": first_action["action"] if first_action else "—",
                "first_by": first_action["user"] if first_action else "—",
                "atual_owner": atual_owner,
            })
            d["alert_sev"][alert_sev(a)] += 1
            d["alert_status"][alert_status_name(a)] += 1
            d["alert_resolution"][res_status] += 1
            d["alert_action_types"][atype] += 1

    for c in cases:
        opened = parse_dt(c.get("initial_date") or c.get("open_date"))
        mh = c.get("modification_history", {})
        events = parse_mod_history(mh)

        close_event = next(
            (e for e in reversed(events) if "closed" in e["action"].lower()), None
        )
        closed = close_event["ts"] if close_event else parse_dt(c.get("close_date"))

        acting_analysts = all_analysts_in_history(events)
        if not acting_analysts:
            owner = c.get("owner")
            if isinstance(owner, dict):
                name = owner.get("user_login") or owner.get("user_name")
                if name and name.lower() not in SYSTEM_USERS:
                    acting_analysts = {normalize_user(name)}
            user = c.get("user")
            if isinstance(user, dict):
                name = user.get("user_login") or user.get("user_name")
                if name and name.lower() not in SYSTEM_USERS:
                    acting_analysts.add(normalize_user(name))

        if not acting_analysts:
            continue

        if analyst_filter:
            acting_analysts = {u for u in acting_analysts if users_match(u, analyst_filter)}
            if not acting_analysts:
                continue

        open_dt_exact = opened
        if not open_dt_exact:
            case_created_event = next(
                (e for e in events if "created" in e["action"].lower()), None
            )
            open_dt_exact = case_created_event["ts"] if case_created_event else None

        close_dt_exact = close_event["ts"] if close_event else parse_dt(c.get("close_date"))

        if open_dt_exact and close_dt_exact and close_dt_exact < open_dt_exact:
            official_close = parse_dt(c.get("close_date"))
            if official_close and official_close >= open_dt_exact:
                close_dt_exact = official_close
            else:
                if debug:
                    print(f"  [DEBUG-CASE #{c.get('case_id')}]")
                    print(f"    close_date bruto: {repr(c.get('close_date'))}")
                    print(f"    official_close: {official_close}")
                    print(f"    open_dt_exact: {open_dt_exact}")
                close_dt_exact = None

        first_action = first_analyst_event(events)
        case_created_time = open_dt_exact

        owner_obj = c.get("owner") or {}
        atual_owner = normalize_user(owner_obj.get("user_login") or owner_obj.get("user_name") or "")

        history_logged = False
        for analyst in acting_analysts:
            d = data[analyst]

            mttr_h = None
            if is_closed(c) and open_dt_exact and close_dt_exact and close_dt_exact >= open_dt_exact:
                mttr_h = (close_dt_exact - open_dt_exact).total_seconds() / 3600
                d["mttr_samples"].append(mttr_h)

            resp_h = None
            if first_action and case_created_time and users_match(first_action["user"], analyst):
                if first_action["ts"] != case_created_time:
                    resp_h = (first_action["ts"] - case_created_time).total_seconds() / 3600
                    if 0 <= resp_h < 720:
                        d["case_response_times"].append(resp_h)

            if not history_logged:
                for e in events:
                    if e["user"].lower() not in SYSTEM_USERS and \
                       e["action"].lower() not in ("alert created", "case created", "created"):
                        d["history_actions"].append({
                            "tipo": "case", "id": c.get("case_id"),
                            "ts": (e["ts"] + BRT_OFFSET).strftime("%d/%m/%Y %H:%M"),
                            "user": e["user"], "action": e["action"],
                        })
                history_logged = True

            entry = {
                "case_id": c.get("case_id"),
                "name": c.get("name","")[:80],
                "severity": case_sev(c),
                "status": "Fechado" if is_closed(c) else "Aberto",
                "customer": (c.get("client") or {}).get("customer_name","?"),
                "open_date": str(c.get("open_date",""))[:10],
                "open_datetime": to_brt(open_dt_exact) if open_dt_exact else str(c.get("open_date",""))[:10],
                "close_date": str(c.get("close_date",""))[:10] if c.get("close_date") else "",
                "close_datetime": to_brt(close_dt_exact) if close_dt_exact else "",
                "mttr_h": round(mttr_h, 1) if mttr_h else None,
                "mttr_fmt": fmt_h(mttr_h),
                "resp_h": round(resp_h, 2) if resp_h is not None else None,
                "resp_fmt": fmt_h(resp_h),
                "first_action": first_action["action"] if first_action else "—",
                "first_by": first_action["user"] if first_action else "—",
                "atual_owner": atual_owner,
            }
            if is_closed(c):
                d["cases_closed"].append(entry)
            else:
                d["cases_open"].append(entry)
            d["case_sev"][case_sev(c)] += 1

    return data

def print_report(data, label, show_alerts, show_cases, show_history, top_alerts, top_cases):
    sep = "=" * 80
    print(f"\n{sep}")
    print(f"  RELATÓRIO DE PRODUTIVIDADE POR ANALISTA — DFIR IRIS")
    print(f"  Período : {label}")
    print(f"  Gerado  : {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print(sep)

    if not data:
        print("\n  Nenhum dado encontrado para o período.\n")
        return

    print(f"\n  {'ANALISTA':<30} {'ALERTAS':>8} {'MTTA':>10} {'MTTR':>10} {'CASES':>6} "
          f"{'ABERTOS':>8} {'FECHADOS':>9} {'MTTR':>9} {'T.RESP.CASE':>12}")
    print(f"  {'-'*110}")
    for analyst, d in sorted(data.items(),
            key=lambda x: -(len(x[1]["alerts"])+len(x[1]["cases_open"])+len(x[1]["cases_closed"]))):
        tc = len(d["cases_open"]) + len(d["cases_closed"])
        mtta = avg(d["alert_response_times"])
        mttr_alert = avg(d["mttr_samples"])
        mttr_case = avg(d["mttr_samples"])
        rc = avg(d["case_response_times"])
        print(f"  {analyst:<30} {len(d['alerts']):>8} {fmt_h(mtta):>10} {fmt_h(mttr_alert):>10} {tc:>6} "
              f"{len(d['cases_open']):>8} {len(d['cases_closed']):>9} "
              f"{fmt_h(mttr_case):>9} {fmt_h(rc):>12}")

    for analyst, d in sorted(data.items(),
            key=lambda x: -(len(x[1]["alerts"])+len(x[1]["cases_open"])+len(x[1]["cases_closed"]))):
        tc = len(d["cases_open"]) + len(d["cases_closed"])
        if len(d["alerts"]) == 0 and tc == 0:
            continue

        print(f"\n\n  {'-'*80}")
        print(f"  ANALISTA: {analyst.upper()}")
        print(f"  {'-'*80}")

        mtta = avg(d["alert_response_times"])
        mttr_alert = avg(d["mttr_samples"])
        print(f"\n  📋 ALERTAS: {len(d['alerts'])}"
              + (f"  |  MTTA médio: {fmt_h(mtta)}" if mtta is not None else "")
              + (f"  |  MTTR médio: {fmt_h(mttr_alert)}" if mttr_alert is not None else ""))
        
        if d["alert_sev"]:
            print("  Severidade : " + " | ".join(
                f"{SEV_ICON.get(s,'')} {s}={d['alert_sev'][s]}"
                for s in SEV_ORDER if d["alert_sev"].get(s)))
        if d["alert_status"]:
            print("  Status     : " + " | ".join(
                f"{k}={v}" for k,v in sorted(d["alert_status"].items())))
        if d["alert_resolution"]:
            print("  Resolução  : " + " | ".join(
                f"{k}={v}" for k,v in sorted(d["alert_resolution"].items())))
        if d["alert_action_types"]:
            print("  Atendimento: " + " | ".join(
                f"{k}={v}" for k,v in
                sorted(d["alert_action_types"].items(), key=lambda x: -x[1])))

        if show_alerts and d["alerts"]:
            print(f"\n  {'ID':>8}  {'DISPONÍVEL':<20} {'SEV':<12} {'STATUS':<15} "
                  f"{'MTTA':>10} {'MTTR':>10}  TÍTULO")
            print(f"  {'-'*110}")
            for a in d["alerts"][:top_alerts]:
                disp = (a.get('available') or a['created'])[:19]
                print(f"  #{a['alert_id']:<7} {disp:<20} "
                      f"{a['severity']:<12} {a['status']:<15} "
                      f"{a['resp_fmt']:>10} {a['mttr_fmt']:>10}  {a['title'][:35]}")
            if len(d["alerts"]) > top_alerts:
                print(f"  ... +{len(d['alerts'])-top_alerts} alertas")

        mttr = avg(d["mttr_samples"])
        rc = avg(d["case_response_times"])
        print(f"\n  📁 CASES: {tc} total  |  {len(d['cases_open'])} abertos  "
              f"|  {len(d['cases_closed'])} fechados"
              + (f"  |  MTTR médio: {fmt_h(mttr)}" if mttr else "")
              + (f"  |  T.Resposta: {fmt_h(rc)}" if rc is not None else ""))

        if show_cases and (d["cases_open"] or d["cases_closed"]):
            all_cases = d["cases_open"] + d["cases_closed"]
            all_cases.sort(key=lambda x: x["open_date"], reverse=True)
            print(f"\n  {'ID':>6}  {'ABERTO':<20} {'FECHADO':<20} {'MTTR':>9} "
                  f"{'T.RESP':>8}  {'SEV':<12} {'STATUS':<10} {'CLIENTE':<15}  NOME")
            print(f"  {'-'*120}")
            for c in all_cases[:top_cases]:
                print(f"  #{c['case_id']:<5} {c.get('open_datetime', c['open_date']):<20} "
                      f"{c.get('close_datetime', c['close_date']) or '—':<20} "
                      f"{c['mttr_fmt']:>9} {c['resp_fmt']:>8}  "
                      f"{c['severity']:<12} {c['status']:<10} "
                      f"{c['customer']:<15}  {c['name'][:35]}")
            if len(all_cases) > top_cases:
                print(f"  ... +{len(all_cases)-top_cases} cases")

    print()

def write_csv(data, label, base_path):
    base = base_path.replace(".csv","")

    def w(path, rows, fields):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            wr = csv.DictWriter(f, fieldnames=fields, delimiter=";", extrasaction="ignore")
            wr.writeheader()
            wr.writerows(rows)
        print(f"  Salvo: {path}  ({len(rows)} linhas)")

    rows_s, rows_c, rows_a, rows_h = [], [], [], []
    for analyst, d in sorted(data.items(),
            key=lambda x: -(len(x[1]["alerts"])+len(x[1]["cases_open"])+len(x[1]["cases_closed"]))):
        tc = len(d["cases_open"]) + len(d["cases_closed"])
        rows_s.append({
            "analista": analyst,
            "total_alertas": len(d["alerts"]),
            "mtta_fmt": fmt_h(avg(d["alert_response_times"])),
            "mtta_h": round(avg(d["alert_response_times"]),2) if avg(d["alert_response_times"]) else "",
            "mttr_alert_fmt": fmt_h(avg(d["mttr_samples"])),
            "mttr_alert_h": round(avg(d["mttr_samples"]),2) if avg(d["mttr_samples"]) else "",
            "fp_count": d["alert_resolution"].get("False Positive",0),
            "nao_classificado": d["alert_resolution"].get("Não classificado",0),
            "vinculado_case": d["alert_action_types"].get("Vinculado a case",0),
            "status_alterado": d["alert_action_types"].get("Status alterado",0),
            "total_cases": tc,
            "cases_abertos": len(d["cases_open"]),
            "cases_fechados": len(d["cases_closed"]),
            "mttr_case_fmt": fmt_h(avg(d["mttr_samples"])),
            "mttr_case_h": round(avg(d["mttr_samples"]),2) if avg(d["mttr_samples"]) else "",
            "tempo_resp_cases": fmt_h(avg(d["case_response_times"])),
            "tempo_resp_cases_h": round(avg(d["case_response_times"]),2) if avg(d["case_response_times"]) else "",
            "periodo": label,
        })
        for c in d["cases_open"] + d["cases_closed"]:
            rows_c.append({"analista": analyst, "periodo": label, **c})
        for a in d["alerts"]:
            rows_a.append({"analista": analyst, "periodo": label, **a})
        for e in d["history_actions"]:
            rows_h.append({"analista": analyst, "periodo": label, **e})

    w(base+"_sumario.csv", rows_s,
      ["analista","total_alertas","mtta_fmt","mtta_h","mttr_alert_fmt","mttr_alert_h",
       "fp_count","nao_classificado","vinculado_case","status_alterado",
       "total_cases","cases_abertos","cases_fechados","mttr_case_fmt","mttr_case_h",
       "tempo_resp_cases","tempo_resp_cases_h","periodo"])
    if rows_c:
        w(base+"_cases.csv", rows_c,
          ["analista","case_id","name","severity","status","customer",
           "open_date","open_datetime","close_date","close_datetime",
           "mttr_fmt","mttr_h","resp_fmt","resp_h",
           "first_action","first_by","atual_owner","periodo"])
    if rows_a:
        w(base+"_alertas.csv", rows_a,
          ["analista","alert_id","title","severity","status","resolution","action_type",
           "customer","created","available","resp_fmt","resp_h","mttr_fmt","mttr_h",
           "first_action","first_by","atual_owner","tags","periodo"])
    if rows_h:
        w(base+"_historico.csv", rows_h,
          ["analista","tipo","id","ts","user","action","periodo"])

def main():
    p = argparse.ArgumentParser(description="Relatório de produtividade — DFIR IRIS")
    p.add_argument("--url", default=IRIS_URL)
    p.add_argument("--token", default=IRIS_TOKEN)
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--date", default=None, metavar="DD/MM/YYYY")
    p.add_argument("--from", dest="date_from", default=None, metavar="DD/MM/YYYY")
    p.add_argument("--to", dest="date_to", default=None, metavar="DD/MM/YYYY")
    p.add_argument("--list-analysts", dest="list_analysts", action="store_true")
    p.add_argument("--analyst", default=None)
    p.add_argument("--no-alerts", action="store_true")
    p.add_argument("--no-cases", action="store_true")
    p.add_argument("--show-alerts", action="store_true")
    p.add_argument("--show-cases", action="store_true")
    p.add_argument("--show-history", action="store_true")
    p.add_argument("--top-alerts", type=int, default=20)
    p.add_argument("--top-cases", type=int, default=50)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--fetch-resolution", action="store_true",
                   help="Modo detalhado: busca histórico completo de cada alerta (LENTO)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out", default=None, help="Arquivo de saída (.json ou .csv)")
    args = p.parse_args()

    if not args.token:
        print("ERRO: IRIS_TOKEN não definido."); raise SystemExit(1)

    date_from, date_to, label = resolve_period(args)
    print(f"\n  Período : {label}")
    if args.analyst: print(f"  Analista: {args.analyst}")
    if args.fetch_resolution:
        print("  ⚠️  MODO DETALHADO: Buscando histórico completo (mais lento)")

    client = IrisClient(args.url, args.token)
    alerts, cases = [], []

    if not args.no_alerts:
        print("Buscando alertas... (use --no-alerts para pular)")
        alerts = client.fetch_alerts(date_from, date_to, analyst_filter=args.analyst)
        print(f"  {len(alerts)} alertas no período.")

    if not args.no_cases:
        print("Buscando cases...")
        cases = client.fetch_cases(date_from, date_to)
        print(f"  {len(cases)} cases no período.")

    data = analyze(alerts, cases, analyst_filter=args.analyst, debug=args.debug,
                   fetch_resolution=args.fetch_resolution,
                   client=client if args.fetch_resolution else None)

    if args.list_analysts:
        print(f"\n  {'ANALISTA':<35} {'ALERTAS':>8} {'CASES':>6} {'MTTA':>10} {'MTTR':>10}")
        print(f"  {'-'*80}")
        for analyst, d in sorted(data.items(),
                key=lambda x: -(len(x[1]["alerts"])+len(x[1]["cases_open"])+len(x[1]["cases_closed"]))):
            tc = len(d["cases_open"]) + len(d["cases_closed"])
            mtta = avg(d["alert_response_times"])
            mttr = avg(d["mttr_samples"])
            print(f"  {analyst:<35} {len(d['alerts']):>8} {tc:>6} "
                  f"{fmt_h(mtta):>10} {fmt_h(mttr):>10}")
        print(f"\n  Use --analyst NOME para ver detalhes")
        return

    if args.json or (args.out and args.out.lower().endswith(".json")):
        out_data = {}
        for analyst, d in data.items():
            out_data[analyst] = {
                "total_alertas": len(d["alerts"]),
                "mtta": fmt_h(avg(d["alert_response_times"])),
                "mtta_h": round(avg(d["alert_response_times"]),2) if avg(d["alert_response_times"]) else None,
                "mttr_alert": fmt_h(avg(d["mttr_samples"])),
                "mttr_alert_h": round(avg(d["mttr_samples"]),2) if avg(d["mttr_samples"]) else None,
                "alertas_por_resolucao": dict(d["alert_resolution"]),
                "alertas_por_atendimento": dict(d["alert_action_types"]),
                "total_cases": len(d["cases_open"])+len(d["cases_closed"]),
                "cases_abertos": len(d["cases_open"]),
                "cases_fechados": len(d["cases_closed"]),
                "mttr_case": fmt_h(avg(d["mttr_samples"])),
                "mttr_case_h": round(avg(d["mttr_samples"]),2) if avg(d["mttr_samples"]) else None,
                "tempo_resposta_cases": fmt_h(avg(d["case_response_times"])),
                "tempo_resposta_cases_h": round(avg(d["case_response_times"]),2) if avg(d["case_response_times"]) else None,
                "alertas": d["alerts"],
                "cases": d["cases_open"] + d["cases_closed"],
                "historico": d["history_actions"],
            }
        out = json.dumps({"periodo": label,
                          "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
                          "analistas": out_data},
                         ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"\nSalvo em {args.out}")
        else:
            print(out)
        return

    if args.out and args.out.lower().endswith(".csv"):
        write_csv(data, label, args.out)
        print_report(data, label, False, False, False, 0, 0)
        return

    print_report(data, label,
                 show_alerts=args.show_alerts,
                 show_cases=args.show_cases,
                 show_history=args.show_history,
                 top_alerts=args.top_alerts,
                 top_cases=args.top_cases)

if __name__ == "__main__":
    main()