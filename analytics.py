import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import yfinance as yf
from sklearn.ensemble import RandomForestRegressor
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from uuid import uuid4
from datetime import timezone
import base64
import sqlite3
import hashlib
import hmac
import secrets
import time
import shutil
import zipfile
import threading
import os
import mimetypes
import json as json_storage
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import json
import re
import html
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, urlparse, parse_qs

st.set_page_config(page_title="NOCTIS Intelligence v32", page_icon="🌌", layout="wide")


def noctis_open_home():
    st.session_state.noctis_show_profile = False
    st.session_state.noctis_show_settings = False
    st.session_state.noctis_show_home = True


def noctis_leave_home():
    st.session_state.noctis_show_home = False


def noctis_go_to(space, group, destination):
    st.session_state.noctis_show_settings=False
    st.session_state.noctis_show_lounge = False
    st.session_state.noctis_show_profile = False
    st.session_state.noctis_show_settings = False
    st.session_state.noctis_show_home = False
    st.session_state.noctis_market_space = space
    if space == "📈 Trading & Crypto":
        st.session_state.noctis_stock_group = group
        if group == "★ My Watchlist":
            return
        if group == "✦ NOCTIS Info":
            st.session_state.noctis_info_navigation = destination
        else:
            st.session_state.noctis_stock_navigation = destination
    else:
        st.session_state.noctis_alt_navigation = destination




# Local profile presets. These are NOT authenticated accounts or private cloud storage.
PROFILE_PATH = Path(__file__).resolve().with_name("noctis_local_profiles.json")

def load_local_profiles():
    try:
        obj = json_storage.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        if isinstance(obj, dict) and isinstance(obj.get("profiles"), dict):
            names = {k: v for k, v in obj["profiles"].items() if isinstance(k, str) and isinstance(v, dict)}
            if names:
                return names
    except (OSError, ValueError, TypeError):
        pass
    # Import the old Home preferences into the default profile on first use.
    try:
        legacy = json_storage.loads(Path(__file__).resolve().with_name("noctis_home_preferences.json").read_text(encoding="utf-8"))
        if not isinstance(legacy, dict):
            legacy = {}
    except (OSError, ValueError, TypeError):
        legacy = {}
    return {"My Profile": legacy}

def save_local_profiles(profiles):
    try:
        PROFILE_PATH.write_text(json_storage.dumps({"profiles": profiles}, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except OSError:
        return False

def choose_market(space):
    st.session_state.noctis_show_profile = False
    st.session_state.noctis_show_settings = False
    st.session_state.noctis_market_space = space
    st.session_state.noctis_show_home = False



# Local authenticated identities. SQLite is for development on one trusted machine.
# Public multi-user deployment requires hosted auth, TLS, rate limiting and managed storage.
ACCOUNT_DB = Path(__file__).resolve().with_name("noctis_accounts_v9.sqlite3")

def account_db():
    con = sqlite3.connect(ACCOUNT_DB, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con

def accounts_init():
    with account_db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS accounts (
          id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          display_name TEXT NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL,
          created_at TEXT NOT NULL)""")

def password_digest(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)

def register_account(username, display_name, password):
    username = username.strip()
    display_name = display_name.strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
        raise ValueError("Username: 3–24 letters, digits or underscores.")
    if not 2 <= len(display_name) <= 32 or any(c in display_name for c in "<>\\"):
        raise ValueError("Display name: 2–32 characters; no markup.")
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Use a password between 12 and 128 characters.")
    salt = os.urandom(16)
    account_id = uuid4().hex
    with account_db() as con:
        try:
            con.execute("INSERT INTO accounts (id,username,display_name,salt,password_hash,created_at) VALUES (?,?,?,?,?,?)", (account_id, username, display_name, salt, password_digest(password, salt), datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            raise ValueError("That username is already taken.") from None
    return {"id": account_id, "username": username, "display_name": display_name}

# Failed login attempts are persisted across reruns/restarts (per username).
# This is local protection, not an internet-facing IP rate limiter.
def security_init():
    with account_db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            failures INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS security_meta (
            key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT OR IGNORE INTO security_meta(key,value) VALUES ('schema_version','11');
        """)

def authenticate_account(username, password):
    username = username.strip()
    now = int(time.time())
    with account_db() as con:
        state = con.execute("SELECT failures,locked_until FROM login_attempts WHERE username=?", (username,)).fetchone()
        if state and state["locked_until"] > now:
            raise ValueError("Too many attempts. Wait a few minutes before trying again.")
        row = con.execute("SELECT * FROM accounts WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    salt = bytes(row["salt"]) if row else b"\0" * 16
    candidate = password_digest(password, salt)
    if row and hmac.compare_digest(candidate, bytes(row["password_hash"])):
        with account_db() as con:
            con.execute("DELETE FROM login_attempts WHERE username=?", (username,))
        return {"id": row["id"], "username": row["username"], "display_name": row["display_name"]}
    with account_db() as con:
        failures = (int(state["failures"]) if state else 0) + 1
        # Five failed attempts -> five minute cooldown; subsequent attempts remain locked.
        lock = now + 300 if failures >= 5 else 0
        con.execute("INSERT INTO login_attempts(username,failures,locked_until) VALUES (?,?,?) "
                    "ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until",
                    (username, failures, lock))
    return None

SESSION_IDLE_SECONDS = 30 * 60

def active_account():
    user = st.session_state.get("noctis_account")
    if not user:
        return None
    now = time.monotonic()
    last = st.session_state.get("noctis_last_activity", now)
    if now - last > SESSION_IDLE_SECONDS:
        st.session_state.pop("noctis_account", None)
        st.session_state.pop("noctis_last_activity", None)
        return None
    with account_db() as con:
        row = con.execute("SELECT id,username,display_name FROM accounts WHERE id=?", (user.get("id"),)).fetchone()
    if not row:
        st.session_state.pop("noctis_account", None)
        return None
    st.session_state.noctis_last_activity = now
    # Never trust a session's display name or account id beyond DB validation.
    return dict(row)

def change_password(account_id, old_password, new_password):
    if not 12 <= len(new_password) <= 128:
        raise ValueError("New password must be 12–128 characters.")
    with account_db() as con:
        row = con.execute("SELECT salt,password_hash FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row or not hmac.compare_digest(password_digest(old_password, bytes(row["salt"])), bytes(row["password_hash"])):
            raise ValueError("Current password is incorrect.")
        salt = os.urandom(16)
        con.execute("UPDATE accounts SET salt=?,password_hash=? WHERE id=?",
                    (salt,password_digest(new_password,salt),account_id))

# v12 local storage utilities. Never restore a database while the app is running.
BACKUP_LOCK = threading.RLock()

def _database_check(path):
    if not path.exists():
        return "Not created yet"
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=15) as con:
        result = con.execute("PRAGMA integrity_check").fetchone()[0]
        return result

def storage_health():
    results = {}
    for label, path in (("Accounts", ACCOUNT_DB), ("Lounge", LOUNGE_DB)):
        try:
            results[label] = {"integrity": _database_check(path), "bytes": path.stat().st_size if path.exists() else 0}
        except (sqlite3.Error, OSError) as exc:
            results[label] = {"integrity": f"ERROR: {exc}", "bytes": 0}
    return results

def _sqlite_snapshot(source, target):
    # SQLite backup API includes committed changes even when WAL is active.
    with sqlite3.connect(source, timeout=15) as src, sqlite3.connect(target, timeout=15) as dest:
        src.backup(dest)
    if _database_check(target) != "ok":
        raise RuntimeError(f"Snapshot verification failed: {source.name}")

def local_backup():
    # Create a self-contained, versioned archive; never delete existing backups.
    with BACKUP_LOCK:
        folder = Path(__file__).resolve().with_name("noctis_backups")
        folder.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        archive = folder / ("noctis_v12_" + stamp + ".zip")
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="noctis_snapshot_") as temporary:
            staging = Path(temporary)
            included = []
            for source in (ACCOUNT_DB, LOUNGE_DB):
                if source.exists():
                    _sqlite_snapshot(source, staging / source.name)
                    included.append(staging / source.name)
            for source in (LOUNGE_PATH, PROFILE_PATH, Path(__file__).resolve().with_name("noctis_home_preferences.json"), Path(__file__).resolve().with_name("noctis_watchlist.json")):
                if source.exists():
                    copy = staging / source.name
                    shutil.copy2(source, copy)
                    included.append(copy)
            manifest = {"format": "noctis-local-backup", "version": 12, "created_utc": datetime.now(timezone.utc).isoformat(), "files": []}
            with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for item in included:
                    data = item.read_bytes()
                    zf.writestr(item.name, data)
                    manifest["files"].append({"path": item.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
                if LOUNGE_MEDIA.exists():
                    for item in sorted(LOUNGE_MEDIA.rglob("*")):
                        if item.is_file() and not item.is_symlink():
                            rel = item.relative_to(LOUNGE_MEDIA)
                            name = "noctis_lounge_media/" + rel.as_posix()
                            data = item.read_bytes()
                            zf.writestr(name, data)
                            manifest["files"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
                zf.writestr("manifest.json", json_storage.dumps(manifest, indent=2))
        # Verify every archived file before reporting success.
        with zipfile.ZipFile(archive) as zf:
            check = json_storage.loads(zf.read("manifest.json"))
            for entry in check["files"]:
                if hashlib.sha256(zf.read(entry["path"])).hexdigest() != entry["sha256"]:
                    raise RuntimeError("Backup verification failed for " + entry["path"])
        return archive

def storage_upgrade_v12():
    # Additive, idempotent schema upgrades; no account or post rows removed.
    with account_db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_utc TEXT NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_accounts_created_at ON accounts(created_at)")
        con.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_utc) VALUES (12,?)", (datetime.now(timezone.utc).isoformat(),))
    with lounge_connection() as con:
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_utc TEXT NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_posts_owner ON posts(account_id,created_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_replies_owner ON replies(account_id,created_at)")
        con.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_utc) VALUES (12,?)", (datetime.now(timezone.utc).isoformat(),))

def storage_status_panel():
    with st.expander("🗄️ LOCAL DATABASE HEALTH & BACKUPS · v12", expanded=False):
        st.caption("SQLite remains local to this computer. This is preparation for a future hosted backend, not online synchronization.")
        for label, status in storage_health().items():
            st.write(f"**{label}:** {status['integrity']} · {status['bytes']:,} bytes")
        st.caption("A backup contains account password hashes and potentially private content. Keep ZIP files private and secure.")
        if st.button("CREATE VERIFIED v12 BACKUP", key="noctis_v12_backup"):
            try:
                path = local_backup()
                st.success("Verified backup created: " + str(path))
            except (OSError, sqlite3.Error, RuntimeError, zipfile.BadZipFile) as exc:
                st.error("Backup failed: " + str(exc))
        st.caption("Restore is intentionally not available in the running app. Close Streamlit before restoring data from a backup.")

security_init()

def account_profile_key():
    account = active_account()
    return "account_" + account["id"] if account else st.session_state.get("noctis_active_profile", "My Profile")


# === NOCTIS v13: opt-in Supabase development community ===
# Separate from all legacy SQLite accounts and posts. Uses ONLY public anon/publishable key.
# Supabase RLS is mandatory; never use a service_role key in Streamlit.
def cloud_config():
    def cfg(key):
        try:
            return str(st.secrets.get(key, os.environ.get(key, ""))).strip()
        except Exception:
            return str(os.environ.get(key, "")).strip()
    url=cfg("SUPABASE_URL").rstrip("/")
    key=cfg("SUPABASE_ANON_KEY")
    if not url or not key: return None
    from urllib.parse import urlparse
    parsed=urlparse(url)
    if parsed.scheme!="https" or not parsed.hostname or not (parsed.hostname.endswith(".supabase.co") or parsed.hostname in ("localhost", "127.0.0.1")):
        raise ValueError("Use a valid HTTPS Supabase project URL ending in .supabase.co.")
    # Reject legacy JWT service role keys by decoding payload when possible.
    if key.count(".")==2:
        try:
            import base64 as _b64
            part=key.split(".")[1]
            role=json.loads(_b64.urlsafe_b64decode(part+"="*((-len(part))%4))).get("role")
            if role=="service_role": raise ValueError("Never put a service_role key in the Streamlit app. Use the anon key.")
        except (ValueError,UnicodeDecodeError,json.JSONDecodeError) as exc:
            if "service_role" in str(exc): raise
    return url,key

def cloud_request(method, path, data=None, *, auth=False, params=None, prefer=None):
    import requests
    config=cloud_config()
    if not config: raise ValueError("Configure SUPABASE_URL and SUPABASE_ANON_KEY first.")
    url,key=config
    headers={"apikey":key,"Content-Type":"application/json","Accept":"application/json"}
    if auth:
        session=cloud_session()
        if not session: raise ValueError("Sign in to the online Lounge first.")
        headers["Authorization"]="Bearer "+session["access_token"]
    else:
        headers["Authorization"]="Bearer "+key
    if prefer: headers["Prefer"]=prefer
    response=requests.request(method,url+path,headers=headers,json=data,params=params,timeout=18)
    if not response.ok:
        try: detail=response.json().get("msg") or response.json().get("message") or response.json().get("error_description") or response.json().get("error")
        except ValueError: detail=None
        raise ValueError(f"Supabase returned {response.status_code}: {str(detail or 'Request failed')[:180]}")
    return response.json() if response.content else None

def cloud_session():
    sess=st.session_state.get("noctis_cloud_session")
    if not sess: return None
    if time.time()<float(sess.get("expires_at",0))-90: return sess
    try:
        result=cloud_request("POST","/auth/v1/token",{"refresh_token":sess["refresh_token"]},params={"grant_type":"refresh_token"})
        return cloud_save_session(result)
    except (ValueError,KeyError):
        st.session_state.pop("noctis_cloud_session",None)
        return None

def cloud_save_session(result):
    if not result or not result.get("access_token"): return None
    user=result.get("user") or {}
    session={"access_token":result["access_token"],"refresh_token":result.get("refresh_token",""),
             "expires_at":time.time()+int(result.get("expires_in",3600)),"user_id":user.get("id"),"email":user.get("email","")}
    st.session_state.noctis_cloud_session=session
    return session

def cloud_login(email,password):
    result=cloud_request("POST","/auth/v1/token",{"email":email.strip(),"password":password},params={"grant_type":"password"})
    return cloud_save_session(result)

def cloud_signup(email,password):
    if len(password)<12: raise ValueError("Use at least 12 characters for your online account password.")
    return cloud_request("POST","/auth/v1/signup",{"email":email.strip(),"password":password})

def cloud_logout():
    sess=st.session_state.get("noctis_cloud_session")
    if sess:
        try: cloud_request("POST","/auth/v1/logout",auth=True)
        except ValueError: pass
    st.session_state.pop("noctis_cloud_session",None)

def cloud_profile():
    sess=cloud_session()
    if not sess: return None
    rows=cloud_request("GET","/rest/v1/noctis_profiles",auth=True,params={"select":"id,handle,display_name,bio,avatar_emoji","id":"eq."+sess["user_id"],"limit":1}) or []
    return rows[0] if rows else None

def cloud_account_panel():
    with st.expander("☁️ ONLINE COMMUNITY · SUPABASE DEV",expanded=False):
        st.caption("Separate from local NOCTIS identity. Only this test community uses Supabase; existing local accounts and posts stay on your PC.")
        try: configured=bool(cloud_config())
        except ValueError as exc:
            st.error(str(exc)); return
        if not configured:
            st.info("Supabase is not configured yet. Follow README_v13.md to create the tables and set Streamlit secrets.")
            return
        sess=cloud_session()
        if sess:
            st.success("Online identity: "+sess.get("email","Signed in"))
            profile=cloud_profile()
            with st.form("cloud_handle_form"):
                handle=st.text_input("Community handle (3–24 letters, numbers, underscores)",value=(profile or {}).get("handle", ""),max_chars=24)
                display_name=st.text_input("Display name",value=(profile or {}).get("display_name") or "",max_chars=48)
                bio=st.text_area("About me",value=(profile or {}).get("bio") or "",max_chars=240)
                avatar=st.selectbox("Avatar badge",["🎱","📈","₿","⚡","🎮","🐟","🌙","🚀"],index=(["🎱","📈","₿","⚡","🎮","🐟","🌙","🚀"].index((profile or {}).get("avatar_emoji")) if (profile or {}).get("avatar_emoji") in ["🎱","📈","₿","⚡","🎮","🐟","🌙","🚀"] else 0))
                if st.form_submit_button("SAVE ONLINE HANDLE"):
                    if not re.fullmatch(r"[A-Za-z0-9_]{3,24}",handle): st.error("Handle must be 3–24 letters, digits or underscores.")
                    else:
                        try:
                            fields={"handle":handle,"display_name":display_name.strip(),"bio":bio.strip(),"avatar_emoji":avatar}
                            if profile:
                                cloud_request("PATCH","/rest/v1/noctis_profiles",fields,auth=True,params={"id":"eq."+sess["user_id"]},prefer="return=minimal")
                            else:
                                cloud_request("POST","/rest/v1/noctis_profiles",{"id":sess["user_id"],**fields},auth=True,prefer="return=minimal")
                            st.success("Online handle saved.")
                        except ValueError as exc: st.error(str(exc))
            if st.button("SIGN OUT OF SUPABASE",key="cloud_logout"):
                cloud_logout(); st.rerun()
        else:
            a,b=st.tabs(["ONLINE SIGN IN","ONLINE SIGN UP"])
            with a:
                with st.form("cloud_login_form"):
                    email=st.text_input("Email",key="cloud_login_email")
                    password=st.text_input("Password",type="password",key="cloud_login_pass")
                    if st.form_submit_button("SIGN IN ONLINE"):
                        try:
                            cloud_login(email,password)
                            st.rerun()
                        except ValueError as exc: st.error(str(exc))
            with b:
                with st.form("cloud_signup_form"):
                    email=st.text_input("Email",key="cloud_signup_email")
                    password=st.text_input("Password (12+ characters)",type="password",key="cloud_signup_pass")
                    if st.form_submit_button("CREATE ONLINE ACCOUNT"):
                        try:
                            result=cloud_signup(email,password)
                            st.success("Signup requested. Check your email for a confirmation link if email verification is enabled, then sign in.")
                        except ValueError as exc: st.error(str(exc))

def cloud_profile_handle(value):
    """Normalize PostgREST embedded profile records (object, list, or null)."""
    if isinstance(value, list):
        value = next((item for item in value if isinstance(item, dict)), {})
    if not isinstance(value, dict):
        return "member"
    handle = value.get("handle")
    return handle.strip() if isinstance(handle, str) and handle.strip() else "member"


def cloud_author_handles(author_ids):
    """Resolve author handles separately, avoiding inconsistent embedded joins."""
    ids = sorted({str(x) for x in author_ids if x})
    if not ids:
        return {}
    # IDs originate from Supabase UUID columns, not user-entered text.
    rows = cloud_request(
        "GET", "/rest/v1/noctis_profiles", auth=True,
        params={"select": "id,handle", "id": "in.(" + ",".join(ids) + ")"}
    ) or []
    if not isinstance(rows, list):
        return {}
    return {
        str(row["id"]): cloud_profile_handle(row)
        for row in rows
        if isinstance(row, dict) and row.get("id")
    }



# === NOCTIS v15: private Supabase media attachments ===
NOCTIS_MEDIA_BUCKET = "noctis-lounge-media"
NOCTIS_MEDIA_MAX_BYTES = 8 * 1024 * 1024

def cloud_media_kind(filename, raw):
    """Allow only a small set of file types; inspect signatures, not only suffixes."""
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".png" and raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if suffix in (".jpg", ".jpeg") and raw.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if suffix == ".webp" and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    if suffix == ".mp4" and len(raw) > 12 and raw[4:8] == b"ftyp":
        return "video/mp4"
    raise ValueError("Only valid PNG, JPG, WebP, and MP4 files are supported.")

def cloud_media_request(method, object_path, *, raw=None, content_type=None, data=None):
    """Storage REST request authenticated as the current user; never service-role."""
    import requests
    from urllib.parse import quote
    config=cloud_config()
    sess=cloud_session()
    if not config or not sess: raise ValueError("Sign in online to use media.")
    base,key=config
    escaped=quote(object_path, safe="/")
    url=base+"/storage/v1/object/"+escaped
    headers={"apikey":key,"Authorization":"Bearer "+sess["access_token"]}
    if content_type: headers["Content-Type"]=content_type
    if method=="POST": headers["x-upsert"]="false"
    try:
        response=requests.request(method,url,headers=headers,data=raw,json=data,timeout=35)
    except requests.RequestException as exc:
        raise ValueError("Unable to reach Supabase Storage: "+str(exc)[:150]) from exc
    if not response.ok:
        try:
            details=response.json()
            message=details.get("message") or details.get("error") or details.get("msg")
        except ValueError: message=None
        raise ValueError(f"Supabase Storage {response.status_code}: {str(message or 'Request failed')[:170]}")
    try: return response.json()
    except ValueError: return None

def cloud_upload_media(upload, user_id):
    if upload is None: return None, None
    raw=upload.getvalue()
    if not raw or len(raw)>NOCTIS_MEDIA_MAX_BYTES:
        raise ValueError("Media must be nonempty and 8 MB or smaller.")
    mime=cloud_media_kind(upload.name,raw)
    from uuid import uuid4
    ext={"image/png":"png","image/jpeg":"jpg","image/webp":"webp","video/mp4":"mp4"}[mime]
    path=f"{user_id}/{uuid4().hex}.{ext}"
    cloud_media_request("POST",f"{NOCTIS_MEDIA_BUCKET}/{path}",raw=raw,content_type=mime)
    return path,mime

def cloud_signed_media_url(path):
    """Short-lived URL for signed-in members; bucket is private."""
    if not path or ".." in path or path.startswith("/"):
        return None
    result=cloud_media_request("POST",f"sign/{NOCTIS_MEDIA_BUCKET}/{path}",data={"expiresIn":300})
    signed=(result or {}).get("signedURL") or (result or {}).get("signedUrl")
    if not isinstance(signed,str): return None
    base,_=cloud_config()
    if signed.startswith("/"):
        return base+(signed if signed.startswith("/storage/v1/") else "/storage/v1"+signed)
    if signed.startswith(base+"/storage/v1/"):
        return signed
    return None

def cloud_display_media(post):
    path=post.get("media_path")
    if not path: return
    try:
        signed=cloud_signed_media_url(path)
        if not signed:
            st.caption("Attachment is unavailable."); return
        if (post.get("media_type") or "").startswith("image/"):
            st.image(signed, width=440)
        elif post.get("media_type")=="video/mp4":
            st.video(signed)
    except ValueError as exc:
        st.caption("Attachment unavailable: "+str(exc))

# === NOCTIS v14: online community features ===
def cloud_members_panel(sess):
    st.markdown("### 👥 NOCTIS MEMBERS")
    members=cloud_request("GET","/rest/v1/noctis_profiles",auth=True,params={"select":"id,handle,display_name,bio,avatar_emoji","order":"handle.asc","limit":100}) or []
    follows=cloud_request("GET","/rest/v1/noctis_follows",auth=True,params={"select":"following_id","follower_id":"eq."+sess["user_id"]}) or []
    following={r["following_id"] for r in follows if isinstance(r,dict) and r.get("following_id")}
    query=st.text_input("Find a member by gamertag",key="cloud_member_search",max_chars=40).strip().lower()
    shown=[m for m in members if isinstance(m,dict) and m.get("id")!=sess["user_id"] and (not query or query in str(m.get("handle","")).lower() or query in str(m.get("display_name","")).lower())]
    st.caption(f"Following {len(following)} member(s) · Showing {min(len(shown),20)}")
    for m in shown[:20]:
        mid=m["id"]
        with st.container(border=True):
            a,b=st.columns([4,1])
            with a:
                st.markdown(f"**{html.escape(m.get('avatar_emoji') or '🎱')} @{html.escape(m.get('handle') or 'member')}** · {html.escape(m.get('display_name') or '')}")
                if m.get("bio"): st.caption(m["bio"])
            with b:
                if st.button("Unfollow" if mid in following else "Follow",key="v14_follow_"+mid):
                    if mid in following:
                        cloud_request("DELETE","/rest/v1/noctis_follows",auth=True,params={"follower_id":"eq."+sess["user_id"],"following_id":"eq."+mid})
                    else:
                        cloud_request("POST","/rest/v1/noctis_follows",{"follower_id":sess["user_id"],"following_id":mid},auth=True,prefer="return=minimal")
                    st.rerun()
    return following

def cloud_notifications_panel(sess):
    st.markdown("### 🔔 NOTIFICATIONS")
    notices=cloud_request("GET","/rest/v1/noctis_notifications",auth=True,params={"select":"id,kind,actor_id,post_id,created_at,read_at","recipient_id":"eq."+sess["user_id"],"order":"created_at.desc","limit":40}) or []
    handles=cloud_author_handles(n.get("actor_id") for n in notices if isinstance(n,dict))
    unread=sum(1 for n in notices if not n.get("read_at"))
    st.caption(f"{unread} unread · Refresh to check for new activity")
    if unread and st.button("Mark all as read",key="v14_mark_read"):
        from datetime import datetime,timezone
        cloud_request("PATCH","/rest/v1/noctis_notifications",{"read_at":datetime.now(timezone.utc).isoformat()},auth=True,params={"recipient_id":"eq."+sess["user_id"],"read_at":"is.null"},prefer="return=minimal")
        st.rerun()
    for n in notices:
        if not isinstance(n,dict): continue
        who=handles.get(str(n.get("actor_id")),"member")
        kind={"follow":"followed you","reply":"replied to your post","reaction":"starred your post"}.get(n.get("kind"),"interacted with you")
        st.markdown(("**● **" if not n.get("read_at") else "")+"**@"+html.escape(who)+"** "+kind)
        st.caption(str(n.get("created_at", ""))[:16].replace("T"," ")+" UTC")
    if not notices: noctis_notice("No notifications yet. Follow someone or start a conversation!","empty_notifications")

# === NOCTIS v16: online member safety and feed controls ===
def cloud_blocked_ids(sess):
    rows=cloud_request("GET","/rest/v1/noctis_blocks",auth=True,params={"select":"blocked_id","blocker_id":"eq."+sess["user_id"]}) or []
    return {str(r.get("blocked_id")) for r in rows if isinstance(r,dict) and r.get("blocked_id")}

def cloud_safety_panel(sess):
    st.markdown("### 🛡️ MEMBER SAFETY")
    st.caption("Blocking hides a member's posts from your feed. Reports are private to moderators; submitting one does not automatically remove content.")
    blocked=cloud_blocked_ids(sess)
    members=cloud_request("GET","/rest/v1/noctis_profiles",auth=True,params={"select":"id,handle","order":"handle.asc","limit":200}) or []
    choices={"@"+str(m.get("handle") or "member")+" · "+str(m["id"])[:8]:str(m["id"]) for m in members if isinstance(m,dict) and m.get("id") and str(m["id"])!=sess["user_id"]}
    if not choices:
        st.info("No other members yet."); return
    choice=st.selectbox("Choose a member",list(choices),key="v16_safety_member")
    target=choices[choice]
    if target in blocked:
        if st.button("UNBLOCK MEMBER",key="v16_unblock"):
            cloud_request("DELETE","/rest/v1/noctis_blocks",auth=True,params={"blocker_id":"eq."+sess["user_id"],"blocked_id":"eq."+target})
            st.rerun()
    elif st.button("BLOCK MEMBER",key="v16_block"):
        cloud_request("POST","/rest/v1/noctis_blocks",{"blocker_id":sess["user_id"],"blocked_id":target},auth=True,prefer="return=minimal")
        st.rerun()
    st.caption(str(len(blocked))+" blocked member(s)")

def cloud_report_post(sess, post_id):
    with st.expander("⚑ Report this post",expanded=False):
        with st.form("v16_report_"+post_id,clear_on_submit=True):
            reason=st.selectbox("Reason",["Spam","Harassment","Scam / misleading promotion","Inappropriate media","Other"],key="v16_reason_"+post_id)
            details=st.text_area("Additional details (optional)",max_chars=500,key="v16_details_"+post_id)
            if st.form_submit_button("SUBMIT REPORT"):
                cloud_request("POST","/rest/v1/noctis_reports",{"reporter_id":sess["user_id"],"post_id":post_id,"reason":reason,"details":details.strip()},auth=True,prefer="return=minimal")
                st.success("Report submitted for review.")

# === NOCTIS v17: mutual-follow friends and private direct messages ===
def cloud_friends_panel(sess):
    st.markdown("### 🤝 FRIENDS & PRIVATE MESSAGES · v21")
    st.caption("Friends are members who follow each other. Only mutual followers can send messages. Messages are stored in your Supabase DEV project; refresh to see new messages.")
    uid=str(sess["user_id"])
    following_rows=cloud_request("GET","/rest/v1/noctis_follows",auth=True,params={"select":"following_id","follower_id":"eq."+uid,"limit":1000}) or []
    follower_rows=cloud_request("GET","/rest/v1/noctis_follows",auth=True,params={"select":"follower_id","following_id":"eq."+uid,"limit":1000}) or []
    following={str(r.get("following_id")) for r in following_rows if isinstance(r,dict)}
    followers={str(r.get("follower_id")) for r in follower_rows if isinstance(r,dict)}
    blocked=cloud_blocked_ids(sess)
    friend_ids=(following & followers)-blocked-{uid}
    # Profiles are public to authenticated members under the existing v14 policies.
    members=cloud_request("GET","/rest/v1/noctis_profiles",auth=True,params={"select":"id,handle,display_name,avatar_emoji","order":"handle.asc","limit":1000}) or []
    friends=[m for m in members if isinstance(m,dict) and str(m.get("id")) in friend_ids]
    st.caption(f"{len(friends)} mutual-follow friend(s) · {len(following-followers)} following you haven't been followed back by")
    if not friends:
        noctis_notice("No mutual-follow friends yet. Visit MEMBERS, follow someone, and ask them to follow you back.","no_mutual_friends")
        return
    # A recipient can read their own unread messages; only participant messages are returned by RLS.
    unread_rows=cloud_request("GET","/rest/v1/noctis_direct_messages",auth=True,params={
        "select":"sender_id","recipient_id":"eq."+uid,"read_at":"is.null","limit":1000}) or []
    unread_counts={}
    for item in unread_rows:
        if isinstance(item,dict):
            sender=str(item.get("sender_id") or "")
            unread_counts[sender]=unread_counts.get(sender,0)+1
    # v20: pins belong to the signed-in account and are protected by Supabase RLS.
    try:
        pin_rows=cloud_request("GET","/rest/v1/noctis_dm_pins",auth=True,params={
            "select":"friend_id","user_id":"eq."+uid,"limit":1000}) or []
        pinned_ids={str(p.get("friend_id")) for p in pin_rows if isinstance(p,dict)}
        pins_available=True
    except ValueError as exc:
        pinned_ids=set()
        pins_available=False
        st.warning("Pinned friends unavailable. Run the v20 SQL migration in Supabase DEV. " + str(exc))
    all_prefs=cloud_request("GET","/rest/v1/noctis_dm_preferences",auth=True,params={"select":"friend_id,muted,archived","user_id":"eq."+uid,"limit":1000}) or []
    prefs_by_friend={str(p.get("friend_id")):p for p in all_prefs if isinstance(p,dict)}
    show_archived=st.checkbox("Show archived conversations",value=False,key="v21_show_archived")
    if not show_archived:
        friends=[m for m in friends if not prefs_by_friend.get(str(m.get("id")),{}).get("archived",False)]
    friends.sort(key=lambda m:(str(m.get("id")) not in pinned_ids,
        -unread_counts.get(str(m.get("id")),0),str(m.get("handle") or "").casefold()))
    st.caption(f"✉️ {sum(unread_counts.values())} unread private message(s) · Use REFRESH to check for new messages")
    friend_search=st.text_input("Find a friend",key="v18_friend_search",placeholder="Search gamertag").strip().casefold()
    visible=[m for m in friends if not friend_search or friend_search in str(m.get("handle") or "").casefold() or friend_search in str(m.get("display_name") or "").casefold()]
    if not visible:
        st.info("No matching friends. Turn on Show archived conversations if needed."); return
    choices={f"{'📌 ' if str(m.get('id')) in pinned_ids else ''}{m.get('avatar_emoji') or '🎱'} @{m.get('handle') or 'member'}"+(f" · {unread_counts.get(str(m['id']),0)} new" if unread_counts.get(str(m['id']),0) else ""):str(m['id']) for m in visible}
    selected=st.selectbox("Conversation",list(choices),key="v17_dm_friend",on_change=lambda: st.session_state.update(v21_dm_offset=0,v21_reply_to=None))
    other=choices[selected]
    if pins_available:
        is_pinned=other in pinned_ids
        if st.button("📌 UNPIN FRIEND" if is_pinned else "📌 PIN FRIEND",key="v20_toggle_pin"):
            try:
                if is_pinned:
                    cloud_request("DELETE","/rest/v1/noctis_dm_pins",auth=True,
                        params={"user_id":"eq."+uid,"friend_id":"eq."+other},prefer="return=minimal")
                else:
                    cloud_request("POST","/rest/v1/noctis_dm_pins",auth=True,
                        data={"user_id":uid,"friend_id":other},prefer="return=minimal")
                st.rerun()
            except ValueError as exc:
                st.error("Could not update pinned friend: "+str(exc))

    # RLS only returns messages where the signed-in user is a participant.
    messages=cloud_request("GET","/rest/v1/noctis_direct_messages",auth=True,params={
        "select":"id,sender_id,recipient_id,body,created_at,read_at,edited_at,reply_to_id",
        "or":f"(and(sender_id.eq.{uid},recipient_id.eq.{other}),and(sender_id.eq.{other},recipient_id.eq.{uid}))",
        "order":"created_at.desc","limit":100,"offset":str(st.session_state.get("v21_dm_offset",0))}) or []
    # Mark only the selected friend's messages to this account as read.
    if any(str(m.get("recipient_id"))==uid and not m.get("read_at") for m in messages if isinstance(m,dict)):
        from datetime import datetime, timezone
        try:
            cloud_request("PATCH","/rest/v1/noctis_direct_messages",
                {"read_at":datetime.now(timezone.utc).isoformat()},auth=True,
                params={"sender_id":"eq."+other,"recipient_id":"eq."+uid,"read_at":"is.null"},prefer="return=minimal")
        except ValueError as exc:
            st.warning("Could not mark messages read: "+str(exc))
    page_offset=int(st.session_state.get("v21_dm_offset",0))
    st.caption(f"Messages {page_offset + 1}–{page_offset + len(messages)} · Newest at the bottom")
    page_left,page_right=st.columns(2)
    with page_left:
        if st.button("← NEWER",key="v21_newer",disabled=page_offset==0):
            st.session_state.v21_dm_offset=max(0,page_offset-100); st.rerun()
    with page_right:
        if st.button("OLDER →",key="v21_older",disabled=len(messages)<100):
            st.session_state.v21_dm_offset=page_offset+100; st.rerun()
    # Per-user mute/archive settings are private under RLS.
    pref_rows=cloud_request("GET","/rest/v1/noctis_dm_preferences",auth=True,params={"select":"muted,archived","user_id":"eq."+uid,"friend_id":"eq."+other,"limit":1}) or []
    pref=pref_rows[0] if pref_rows else {"muted":False,"archived":False}
    with st.expander("Conversation settings"):
        mute=st.checkbox("Mute conversation",value=bool(pref.get("muted")),key="v21_mute_"+other)
        archive=st.checkbox("Archive conversation",value=bool(pref.get("archived")),key="v21_archive_"+other)
        if st.button("SAVE CONVERSATION SETTINGS",key="v21_save_pref"):
            cloud_request("POST","/rest/v1/noctis_dm_preferences",{"user_id":uid,"friend_id":other,"muted":mute,"archived":archive},auth=True,prefer="resolution=merge-duplicates,return=minimal")
            st.success("Conversation preferences saved."); st.rerun()
    # A reaction is visible only to participants; sender can edit their own messages.
    msg_ids=[str(m["id"]) for m in messages if isinstance(m,dict) and m.get("id")]
    reaction_rows=cloud_request("GET","/rest/v1/noctis_dm_reactions",auth=True,params={"select":"message_id,user_id,emoji","message_id":"in.("+",".join(msg_ids)+")","limit":1000}) if msg_ids else []
    reaction_map={}
    for r in reaction_rows or []:
        reaction_map.setdefault(str(r["message_id"]),[]).append(r)
    body_by_id={str(m["id"]):str(m.get("body") or "") for m in messages if isinstance(m,dict)}
    dm_search=st.text_input("Search this conversation",key="v19_dm_search",placeholder="Find a word in the latest 100 messages").strip().casefold()
    if dm_search:
        messages=[m for m in messages if isinstance(m,dict) and dm_search in str(m.get("body") or "").casefold()]
        st.caption(f"{len(messages)} matching message(s) in the latest 100")
    if not messages: st.info("No messages yet. Say hello!")
    for msg in reversed(messages):
        if not isinstance(msg,dict): continue
        sender="You" if str(msg.get("sender_id"))==uid else selected
        with st.container(border=True):
            st.markdown("**"+html.escape(sender)+"** · "+html.escape(str(msg.get("created_at") or "")[:16].replace("T"," "))+" UTC")
            if msg.get("reply_to_id"):
                quote=body_by_id.get(str(msg["reply_to_id"]),"Earlier message")
                st.caption("↳ Reply to: "+quote[:120])
            st.write(msg.get("body") or "")
            if msg.get("edited_at"): st.caption("Edited")
            reactions=reaction_map.get(str(msg["id"]),[])
            if reactions:
                st.caption(" ".join(f"{emoji} {sum(1 for r in reactions if r['emoji']==emoji)}" for emoji in sorted({r['emoji'] for r in reactions})))
            with st.popover("↩ Reply / React"):
                if st.button("Reply to this message",key="v21_reply_"+str(msg["id"])):
                    st.session_state.v21_reply_to=str(msg["id"]); st.rerun()
                selected_emoji=st.selectbox("Reaction",["👍","❤️","😂","🔥","🎱"],key="v21_emoji_"+str(msg["id"]))
                if st.button("Toggle reaction",key="v21_toggle_"+str(msg["id"])):
                    existing=next((r for r in reactions if str(r.get("user_id"))==uid and r.get("emoji")==selected_emoji),None)
                    if existing:
                        cloud_request("DELETE","/rest/v1/noctis_dm_reactions",auth=True,params={"message_id":"eq."+str(msg["id"]),"user_id":"eq."+uid,"emoji":"eq."+selected_emoji},prefer="return=minimal")
                    else:
                        cloud_request("POST","/rest/v1/noctis_dm_reactions",{"message_id":str(msg["id"]),"user_id":uid,"emoji":selected_emoji},auth=True,prefer="return=minimal")
                    st.rerun()
            if str(msg.get("sender_id"))==uid:
                st.caption("✓✓ Read" if msg.get("read_at") else "✓ Sent")
                with st.popover("Message options"):
                    revised=st.text_area("Edit message",value=str(msg.get("body") or ""),max_chars=1000,key="v21_edit_"+str(msg["id"]))
                    if st.button("SAVE EDIT",key="v21_save_edit_"+str(msg["id"])):
                        if not revised.strip(): st.warning("Message cannot be empty.")
                        else:
                            cloud_request("PATCH","/rest/v1/noctis_direct_messages",{"body":revised.strip()},auth=True,params={"id":"eq."+str(msg["id"]),"sender_id":"eq."+uid},prefer="return=minimal")
                            st.rerun()
                    st.caption("Unsend permanently deletes this message for both participants.")
                    confirm=st.checkbox("I understand this cannot be undone",key="v19_confirm_"+str(msg.get("id")))
                    if st.button("UNSEND MESSAGE",key="v19_unsend_"+str(msg.get("id")),disabled=not confirm):
                        try:
                            cloud_request("DELETE","/rest/v1/noctis_direct_messages",auth=True,
                                params={"id":"eq."+str(msg["id"]),"sender_id":"eq."+uid},prefer="return=minimal")
                            st.rerun()
                        except ValueError as exc:
                            st.error("Could not unsend message: "+str(exc))
    with st.form("v17_dm_compose",clear_on_submit=True):
        reply_id=st.session_state.get("v21_reply_to")
        if reply_id: st.caption("↳ Replying to: "+body_by_id.get(str(reply_id),"Earlier message")[:120])
        body=st.text_area("Private message",max_chars=1000,key="v17_dm_body")
        if st.form_submit_button("SEND MESSAGE"):
            if not body.strip(): st.warning("Type a message first.")
            else:
                try:
                    payload={"sender_id":uid,"recipient_id":other,"body":body.strip()}
                    if reply_id: payload["reply_to_id"]=reply_id
                    cloud_request("POST","/rest/v1/noctis_direct_messages",payload,auth=True,prefer="return=minimal")
                    st.session_state.pop("v21_reply_to",None)
                    st.success("Message sent.")
                    st.rerun()
                except ValueError as exc:
                    st.error("Message not sent: "+str(exc))
    if st.session_state.get("v21_reply_to") and st.button("CANCEL REPLY",key="v21_cancel_reply"):
        st.session_state.pop("v21_reply_to",None); st.rerun()
    if st.button("↻ REFRESH MESSAGES",key="v17_dm_refresh"): st.rerun()

def cloud_friends_directory(sess):
    st.markdown("### 🤝 MY FRIENDS")
    uid=str(sess["user_id"])
    following=cloud_request("GET","/rest/v1/noctis_follows",auth=True,params={"select":"following_id","follower_id":"eq."+uid,"limit":1000}) or []
    followers=cloud_request("GET","/rest/v1/noctis_follows",auth=True,params={"select":"follower_id","following_id":"eq."+uid,"limit":1000}) or []
    mutual={str(r.get("following_id")) for r in following if isinstance(r,dict)} & {str(r.get("follower_id")) for r in followers if isinstance(r,dict)}
    mutual-=cloud_blocked_ids(sess)
    members=cloud_request("GET","/rest/v1/noctis_profiles",auth=True,params={"select":"id,handle,display_name,avatar_emoji","order":"handle.asc","limit":1000}) or []
    query=st.text_input("Search friends",key="v22_friend_directory_search").strip().casefold()
    shown=[m for m in members if isinstance(m,dict) and str(m.get("id")) in mutual and (not query or query in str(m.get("handle") or "").casefold() or query in str(m.get("display_name") or "").casefold())]
    st.caption(f"{len(mutual)} mutual-follow friends")
    if not shown: noctis_notice("No matching friends. Follow someone in Members and have them follow you back.","empty_friends")
    for m in shown:
        with st.container(border=True):
            st.markdown(f"{html.escape(str(m.get('avatar_emoji') or '🎱'))} **@{html.escape(str(m.get('handle') or 'member'))}** · {html.escape(str(m.get('display_name') or ''))}")
            if st.button("✉️ Open messages",key="v22_friend_open_"+str(m["id"])):
                st.session_state.v22_lounge_view="✉️ Messages"
                st.rerun()


# v26: optional, local-only dismissal for guidance notices. No Supabase migration.
NOCTIS_DISMISSED_NOTICES_PATH=Path(__file__).resolve().with_name("noctis_dismissed_notices.json")
def noctis_notice(message, notice_id):
    key=noctis_appearance_key()+":"+str(notice_id)
    if key in st.session_state.get("v26_hidden_notices",set()): return
    try:
        saved=json_storage.loads(NOCTIS_DISMISSED_NOTICES_PATH.read_text(encoding="utf-8"))
        if not isinstance(saved,dict): saved={}
    except (OSError,ValueError,TypeError): saved={}
    if saved.get(key): return
    left,right=st.columns([7,2],vertical_alignment="center")
    with left: st.info(message)
    with right:
        with st.popover("⋯ Notice options",use_container_width=True):
            if st.button("Hide until next visit",key="v26_hide_"+notice_id,use_container_width=True):
                hidden=st.session_state.setdefault("v26_hidden_notices",set())
                hidden.add(key); st.rerun()
            if st.button("Don't show again",key="v26_never_"+notice_id,use_container_width=True):
                saved[key]=True
                try: NOCTIS_DISMISSED_NOTICES_PATH.write_text(json_storage.dumps(saved,indent=2),encoding="utf-8")
                except OSError: st.warning("Could not save notice preference on this computer.")
                else: st.rerun()

def cloud_lounge_page():
    # Reuse the recognizable local Lounge green without replacing the default NOCTIS theme.
    st.markdown("""<style>
    .online-lounge-hero{padding:23px 27px;border:1px solid #4f995e;border-radius:20px;background:radial-gradient(ellipse at 90% 5%,#285e3c,#131f20 57%,#171227);box-shadow:0 8px 35px #0005;margin-bottom:16px}
    .online-lounge-hero h1{color:#e4ffe2;font-size:2rem;margin:7px 0;letter-spacing:1px}
    .online-lounge-hero p{color:#b6d5c1;margin:0;font-size:.92rem}
    .online-lounge-tag{display:inline-block;border:1px solid #53895c;border-radius:999px;padding:3px 11px;color:#baf5bd;font-size:.73rem;letter-spacing:1px;font-weight:700}
    .online-lounge-subhead{color:#b6d5c1;font-size:.82rem;letter-spacing:.07em;text-transform:uppercase;margin-top:7px}
    .st-key-v24_community_nav [data-testid="stSegmentedControl"]{border-radius:15px}
    </style>""",unsafe_allow_html=True)
    st.markdown("""<style>
    /* v26 visual system: large, distinct navigation tiles and quieter feed */
    .online-lounge-hero{padding:34px 35px!important;border-radius:24px!important;box-shadow:0 18px 45px #0007, inset 0 1px 0 #9cf5a533!important}
    .online-lounge-hero h1{font-size:clamp(1.6rem,3.3vw,2.5rem)!important;letter-spacing:.045em!important}
    .v26-nav-caption{min-height:53px;border:1px solid #365a47;border-bottom:0;border-radius:16px 16px 0 0;background:linear-gradient(135deg,#182b25,#141d25);padding:10px 13px 4px;margin-top:9px}
    .v26-nav-caption strong{display:block;color:#e2fbe6;font-size:12px;letter-spacing:.13em}
    .v26-nav-caption small{display:block;color:#9fb5ac;font-size:11px;margin-top:3px}
    .v26-nav-selected{border-color:#70d98a;background:linear-gradient(135deg,#214634,#1b2a32);box-shadow:0 -4px 22px #3eac6530}
    [class*='st-key-v26_nav_'] button{width:100%;min-height:53px!important;border-radius:0 0 15px 15px!important;border:1px solid #456e54!important;font-size:13px!important;font-weight:750!important;letter-spacing:.02em!important;background:#16251e!important;color:#c6e6d1!important;box-shadow:0 8px 18px #0003!important}
    [class*='st-key-v26_nav_'] button[kind='primary']{background:linear-gradient(120deg,#306c46,#1d513e)!important;border-color:#76d28c!important;color:#fff!important;box-shadow:0 0 0 1px #5cad6d55,0 10px 24px #1a8a4730!important}
    [class*='st-key-v26_nav_'] button:hover{border-color:#9bf5b0!important;transform:translateY(-1px)}
    .v26-section-rule{height:1px;background:linear-gradient(90deg,transparent,#5f986e,transparent);margin:23px 0}
    /* Feed panels use more breathing room without touching stored posts */
    [data-testid='stVerticalBlockBorderWrapper']{border-radius:16px!important}
    [data-testid='stExpander']{border-radius:14px!important}
    </style>""",unsafe_allow_html=True)
    st.markdown("<div class='online-lounge-hero'><span class='online-lounge-tag'>✦ NOCTIS SOCIAL</span> <span class='online-lounge-tag'>ONLINE DEV</span><h1>🎱 THE BILLIARDS LOUNGE</h1><p>Choose your room. Find your people. Join the conversation.</p></div>",unsafe_allow_html=True)
    try:
        if not cloud_config():
            st.info("Configure Supabase in My Profile → Online Account."); return
        sess=cloud_session()
        if not sess:
            st.warning("Sign in through My Profile to access online discussions."); return
        profile=cloud_profile()
        if not profile:
            st.warning("Create your online handle in My Profile before posting or replying.")
        st.markdown("<div class='online-lounge-subhead'>EXPLORE THE COMMUNITY</div>",unsafe_allow_html=True)
        st.markdown("""<style>
    /* v27 Lounge identity accents are fixed, independent of Settings palette. */
    .v26-nav-caption{position:relative;overflow:hidden}
    .v26-nav-caption:before{content:'';position:absolute;inset:0 auto 0 0;width:4px;background:#58c98d}
    .v27-community-note{background:linear-gradient(110deg,#1b2e35,#201d30);border:1px solid #57757c;border-radius:15px;padding:14px 18px;margin:12px 0 20px;color:#cce2ea;font-size:13px}
    .online-lounge-hero{background:radial-gradient(ellipse at 90% 5%,#2d7051,#15242b 53%,#241c38)!important;border-color:#5ba58e!important}
    [class*='st-key-v26_nav_MEMBERS'] button{border-color:#508bb1!important}
    [class*='st-key-v26_nav_FRIENDS'] button{border-color:#9574c4!important}
    [class*='st-key-v26_nav_MESSAGES'] button{border-color:#619eb0!important}
    [class*='st-key-v26_nav_ACTIVITY'] button{border-color:#c29b5c!important}
    [class*='st-key-v26_nav_SAFETY'] button{border-color:#b27a9b!important}
    </style>""",unsafe_allow_html=True)
        st.markdown("<div class='v27-community-note'>✦ Your community, your pace. Pick a section above to focus on one thing at a time.</div>",unsafe_allow_html=True)
        # v26: genuine six-card navigation, not a cramped segmented strip.
        community_destinations=[("💬 Discussions","DISCUSSIONS","Explore rooms and posts"),("👥 Members","MEMBERS","Find people"),("🤝 Friends","FRIENDS","Your circle"),("✉️ Messages","MESSAGES","Private inbox"),("🔔 Notifications","ACTIVITY","Latest updates"),("🛡️ Safety","SAFETY","Privacy tools")]
        if "v26_community_view" not in st.session_state:
            st.session_state.v26_community_view="💬 Discussions"
        for row_start in (0,3):
            columns=st.columns(3,gap="small")
            for column,(destination,title,description) in zip(columns,community_destinations[row_start:row_start+3]):
                with column:
                    selected=st.session_state.v26_community_view==destination
                    st.markdown(f"<div class='v26-nav-caption {'v26-nav-selected' if selected else ''}'><strong>{html.escape(title)}</strong><small>{html.escape(description)}</small></div>",unsafe_allow_html=True)
                    if st.button(destination,key="v26_nav_"+title,use_container_width=True,type="primary" if selected else "secondary"):
                        st.session_state.v26_community_view=destination
                        st.rerun()
        view=st.session_state.v26_community_view
        st.markdown("<div class='v26-section-rule'></div>",unsafe_allow_html=True)
        if view=="👥 Members":
            cloud_members_panel(sess)
        elif view=="🤝 Friends":
            cloud_friends_directory(sess)
        elif view=="✉️ Messages":
            cloud_friends_panel(sess)
        elif view=="🔔 Notifications":
            cloud_notifications_panel(sess)
        elif view=="🛡️ Safety":
            cloud_safety_panel(sess)
        else:
            st.markdown("#### 💬 Discussions")
            st.caption("Room-based conversations · Your feed stays separate from members and messages")
            room=st.selectbox("🎱 CHOOSE A ROOM",list(LOUNGE_ROOM_INFO),key="cloud_room")
            with st.container(border=True):
                filter_left,filter_right=st.columns([2,1])
                with filter_left:
                    feed_mode=st.segmented_control("Feed",["Everyone","Following"],default="Everyone",key="v14_feed_mode") or "Everyone"
                with filter_right:
                    sort_mode=st.selectbox("Sort",["Newest first","Oldest first","Most stars"],key="v16_sort")
                search_term=st.text_input("Search discussions",placeholder="Search titles, posts, or members…",key="v16_search",label_visibility="collapsed").strip().casefold()
            if profile:
                with st.expander("✚ CREATE A POST",expanded=False):
                    st.caption("Start a new discussion in the selected room. The editor stays out of the way until you open it.")
                    with st.form("cloud_post_form",clear_on_submit=True):
                        title=st.text_input("Post title",max_chars=120)
                        body=st.text_area("Your research / discussion",max_chars=4000)
                        media=st.file_uploader("Optional image or video (PNG, JPG, WebP, MP4 · max 8 MB)",type=["png","jpg","jpeg","webp","mp4"],key="v15_cloud_media")
                        if st.form_submit_button("PUBLISH TO ONLINE LOUNGE"):
                            if not title.strip() or not body.strip(): st.error("Title and message are required.")
                            else:
                                uploaded_path=None
                                try:
                                    uploaded_path,mime=cloud_upload_media(media,sess["user_id"])
                                    payload={"author_id":sess["user_id"],"room":room,"title":title.strip(),"body":body.strip()}
                                    if uploaded_path: payload.update(media_path=uploaded_path,media_type=mime)
                                    cloud_request("POST","/rest/v1/noctis_posts",payload,auth=True,prefer="return=minimal")
                                    st.success("Post shared with online test members."); st.rerun()
                                except ValueError as exc:
                                    if uploaded_path:
                                        try: cloud_media_request("DELETE",f"{NOCTIS_MEDIA_BUCKET}/{uploaded_path}")
                                        except ValueError: pass
                                    st.error("Could not publish: "+str(exc))
            if st.button("↻ REFRESH ONLINE POSTS",key="cloud_refresh"): st.rerun()
            posts=cloud_request("GET","/rest/v1/noctis_posts",auth=True,params={"select":"id,author_id,room,title,body,created_at,media_path,media_type","room":"eq."+room,"order":"created_at.desc","limit":100}) or []
            if not isinstance(posts, list):
                st.error("Unexpected post data from Supabase."); return
            if feed_mode=="Following":
                follows=cloud_request("GET","/rest/v1/noctis_follows",auth=True,params={"select":"following_id","follower_id":"eq."+sess["user_id"]}) or []
                ids={f.get("following_id") for f in follows if isinstance(f,dict)} | {sess["user_id"]}
                posts=[p for p in posts if isinstance(p,dict) and p.get("author_id") in ids]
            blocked=cloud_blocked_ids(sess)
            posts=[p for p in posts if isinstance(p,dict) and str(p.get("author_id")) not in blocked]
            post_handles = cloud_author_handles(p.get("author_id") for p in posts if isinstance(p, dict))
            if search_term:
                posts=[p for p in posts if search_term in " ".join([str(p.get("title") or ""),str(p.get("body") or ""),post_handles.get(str(p.get("author_id")),"")]).casefold()]
            if sort_mode=="Oldest first":
                posts.reverse()
            elif sort_mode=="Most stars":
                # Fetch counts in one request rather than one request per candidate.
                ids=[str(p["id"]) for p in posts]
                if ids:
                    all_reactions=cloud_request("GET","/rest/v1/noctis_reactions",auth=True,params={"select":"post_id","post_id":"in.("+",".join(ids)+")","limit":1000}) or []
                    from collections import Counter
                    counts=Counter(str(r.get("post_id")) for r in all_reactions if isinstance(r,dict))
                    posts.sort(key=lambda p:(counts.get(str(p["id"]),0),str(p.get("created_at") or "")),reverse=True)
            st.caption(f"Showing {len(posts)} discussion(s) · up to 100 recent posts loaded per room")
            if not posts: noctis_notice("No matching online posts in this room.","empty_online_room")
            for post in posts:
                if not isinstance(post, dict):
                    continue
                with st.container(border=True):
                    author=post_handles.get(str(post.get("author_id")), "member")
                    st.markdown("#### "+html.escape(post["title"]))
                    st.caption("@"+author+" · "+post["created_at"][:16].replace("T"," ")+" UTC")
                    st.write(post["body"])
                    cloud_display_media(post)
                    pid=post["id"]
                    with st.popover("⋯ Post options"):
                        cloud_report_post(sess,pid)
                    reactions=cloud_request("GET","/rest/v1/noctis_reactions",auth=True,params={"select":"user_id","post_id":"eq."+pid}) or []
                    mine=any(r["user_id"]==sess["user_id"] for r in reactions)
                    left,right=st.columns([1,3])
                    with left:
                        if st.button(("★" if mine else "☆")+f" {len(reactions)}",key="cloud_star_"+pid):
                            if mine: cloud_request("DELETE","/rest/v1/noctis_reactions",auth=True,params={"post_id":"eq."+pid,"user_id":"eq."+sess["user_id"]})
                            else: cloud_request("POST","/rest/v1/noctis_reactions",{"post_id":pid,"user_id":sess["user_id"]},auth=True,prefer="return=minimal")
                            st.rerun()
                    with right:
                        if post["author_id"]==sess["user_id"] and st.button("DELETE MY POST",key="cloud_delete_"+pid):
                            cloud_request("DELETE","/rest/v1/noctis_posts",auth=True,params={"id":"eq."+pid})
                            if post.get("media_path"):
                                try: cloud_media_request("DELETE",f"{NOCTIS_MEDIA_BUCKET}/{post['media_path']}")
                                except ValueError: st.warning("Post deleted; attachment cleanup failed. Remove the orphaned file from Storage manually.")
                            st.rerun()
                    replies=cloud_request("GET","/rest/v1/noctis_replies",auth=True,params={"select":"id,author_id,body,created_at","post_id":"eq."+pid,"order":"created_at.asc","limit":100}) or []
                    if not isinstance(replies, list):
                        replies = []
                    with st.expander(f"💬 {len(replies)} replies · Open conversation",expanded=False):
                        reply_handles = cloud_author_handles(r.get("author_id") for r in replies if isinstance(r, dict))
                        for reply in replies:
                            if not isinstance(reply, dict):
                                continue
                            rauthor=reply_handles.get(str(reply.get("author_id")), "member")
                            st.markdown("**@"+html.escape(rauthor)+"** · "+html.escape(reply["body"]))
                        if profile:
                            with st.form("cloud_reply_"+pid,clear_on_submit=True):
                                answer=st.text_input("Reply",max_chars=700,key="cloud_reply_text_"+pid)
                                if st.form_submit_button("SEND REPLY"):
                                    if answer.strip():
                                        cloud_request("POST","/rest/v1/noctis_replies",{"post_id":pid,"author_id":sess["user_id"],"body":answer.strip()},auth=True,prefer="return=minimal")
                                        st.rerun()
    except ValueError as exc:
        st.error("Online Lounge: "+str(exc))
        if any(k in str(exc) for k in ("noctis_direct_messages","read_at","noctis_follows","noctis_notifications","display_name","media_path","media_type","noctis-lounge-media","noctis_blocks","noctis_reports")):
            st.info("Make sure all NOCTIS SQL upgrades through v18 have been run in your Supabase DEV SQL Editor, then refresh.")
# === End v13 Supabase bridge ===


def home_account_panel():
    st.markdown("### ◈ NOCTIS IDENTITY")
    account = active_account()
    if account:
        st.success("Signed in as @" + account["username"] + " · " + account["display_name"])
        st.caption("Your private Home preferences are stored under this local account. Sessions expire after 30 minutes without app activity.")
        with st.expander("🔐 ACCOUNT SECURITY", expanded=False):
            with st.form("noctis_change_password_form"):
                current = st.text_input("Current password", type="password")
                new = st.text_input("New password (12+ characters)", type="password")
                confirm = st.text_input("Confirm new password", type="password")
                if st.form_submit_button("CHANGE PASSWORD"):
                    if new != confirm:
                        st.error("New passwords do not match.")
                    else:
                        try:
                            change_password(account["id"], current, new)
                            st.session_state.pop("noctis_account", None)
                            st.success("Password updated. Sign in again.")
                        except ValueError as exc:
                            st.error(str(exc))
            st.caption("Back up local account and Lounge data before making major upgrades.")
            if st.button("CREATE LOCAL BACKUP", key="noctis_backup"):
                try:
                    location = local_backup()
                    st.success(f"Verified backup saved locally: {location}")
                except (OSError,sqlite3.Error) as exc:
                    st.error(f"Backup failed: {exc}")
        storage_status_panel()
        if st.button("Sign out", key="noctis_sign_out"):
            st.session_state.pop("noctis_account", None)
            st.session_state.pop("noctis_last_activity", None)
            st.rerun()
    else:
        st.info("Browsing as a guest. Sign in to publish, reply or react in the Lounge.")
        signin, signup = st.tabs(["SIGN IN", "CREATE ACCOUNT"])
        with signin:
            with st.form("noctis_login_form"):
                username = st.text_input("Username", key="noctis_login_name")
                password = st.text_input("Password", type="password", key="noctis_login_pass")
                if st.form_submit_button("SIGN IN"):
                    try:
                        user = authenticate_account(username, password)
                        if user:
                            st.session_state.noctis_account = user
                            st.session_state.noctis_last_activity = time.monotonic()
                            st.rerun()
                        else:
                            st.error("Incorrect username or password.")
                    except ValueError as exc:
                        st.error(str(exc))
        with signup:
            with st.form("noctis_register_form"):
                username = st.text_input("New username", key="noctis_register_name")
                display_name = st.text_input("Display name / gamertag", key="noctis_register_display")
                password = st.text_input("New password (12+ characters)", type="password", key="noctis_register_pass")
                confirmation = st.text_input("Confirm password", type="password", key="noctis_register_confirm")
                if st.form_submit_button("CREATE LOCAL ACCOUNT"):
                    if password != confirmation:
                        st.error("Passwords do not match.")
                    else:
                        try:
                            st.session_state.noctis_account = register_account(username, display_name, password)
                            st.session_state.noctis_last_activity = time.monotonic()
                            st.rerun()
                        except (ValueError, sqlite3.Error) as exc:
                            st.error(str(exc))
    st.caption("LOCAL DEVELOPMENT ONLY · No email verification, password reset or online identity sync. Never reuse an important password here.")

accounts_init()

# Billiards Lounge: local-only shared board for local profile presets.
LOUNGE_PATH = Path(__file__).resolve().with_name("noctis_lounge_posts.json")
LOUNGE_MEDIA = Path(__file__).resolve().with_name("noctis_lounge_media")
LOUNGE_ROOMS = ["📈 Stocks & Day Trading", "₿ Bitcoin & Crypto", "⚡ Pokémon Cards", "🏟 Sports & Predictions", "🎱 General Lounge"]

def noctis_open_lounge():
    st.session_state.noctis_show_profile = False
    st.session_state.noctis_show_settings = False
    st.session_state.noctis_show_home = False
    st.session_state.noctis_show_lounge = True

def noctis_open_home():
    st.session_state.noctis_show_profile = False
    st.session_state.noctis_show_settings = False
    st.session_state.noctis_show_home = True
    st.session_state.noctis_show_lounge = False

def choose_market(space):
    st.session_state.noctis_show_profile = False
    st.session_state.noctis_show_settings = False
    st.session_state.noctis_market_space = space
    st.session_state.noctis_show_home = False
    st.session_state.noctis_show_lounge = False

# SQLite-backed local community. This is NOT authentication or an internet chat.
LOUNGE_DB = Path(__file__).resolve().with_name("noctis_lounge_v8.sqlite3")
LOUNGE_ROOM_INFO = {
    "📈 Stocks & Day Trading": ("MARKET FLOOR", "Charts, trade plans, earnings, and risk management", "📈"),
    "₿ Bitcoin & Crypto": ("THE BLOCK", "Bitcoin, altcoins, blockchain and market cycles", "₿"),
    "⚡ Pokémon Cards": ("THE CARD TABLE", "Collecting, grading, sets, prices and pulls", "⚡"),
    "🏟 Sports & Predictions": ("THE SCOREBOARD", "Games, statistics, probabilities and prediction research", "🏟"),
    "🎱 General Lounge": ("THE CORNER BOOTH", "Meet the community, ask questions, share ideas", "🎱"),
}

def lounge_connection():
    con = sqlite3.connect(LOUNGE_DB, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA journal_mode=WAL")
    return con

def lounge_init():
    with lounge_connection() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS lounge_meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS posts (
          id TEXT PRIMARY KEY, room TEXT NOT NULL, author TEXT NOT NULL,
          title TEXT NOT NULL, body TEXT NOT NULL, link TEXT NOT NULL DEFAULT '',
          media_file TEXT, media_kind TEXT, created_at TEXT NOT NULL,
          edited_at TEXT, topic TEXT NOT NULL DEFAULT 'Discussion',
          symbol TEXT NOT NULL DEFAULT '', pinned INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS replies (
          id TEXT PRIMARY KEY, post_id TEXT NOT NULL, author TEXT NOT NULL,
          body TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(post_id) REFERENCES posts(id)
        );
        CREATE TABLE IF NOT EXISTS reactions (
          post_id TEXT NOT NULL, author TEXT NOT NULL, kind TEXT NOT NULL,
          PRIMARY KEY(post_id,author,kind)
        );
        CREATE INDEX IF NOT EXISTS idx_lounge_room ON posts(room,created_at);
        CREATE INDEX IF NOT EXISTS idx_lounge_replies ON replies(post_id);
        """)
        # Legacy rows remain visible but unclaimed. They cannot be modified by a new account.
        for table in ("posts", "replies", "reactions"):
            cols = {row[1] for row in con.execute("PRAGMA table_info(" + table + ")")}
            if "account_id" not in cols:
                con.execute("ALTER TABLE " + table + " ADD COLUMN account_id TEXT")
        # One-time import from v7 JSON, preserving earlier local posts and replies.
        if not con.execute("SELECT 1 FROM lounge_meta WHERE key='v7_import_checked'").fetchone() and LOUNGE_PATH.exists():
            try:
                legacy = json_storage.loads(LOUNGE_PATH.read_text(encoding="utf-8"))
                if isinstance(legacy,list):
                    for item in legacy:
                        if not isinstance(item,dict): continue
                        pid = str(item.get("id") or uuid4().hex)
                        media = item.get("media") or {}
                        con.execute("INSERT OR IGNORE INTO posts (id,room,author,title,body,link,media_file,media_kind,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                                    (pid,str(item.get("room","🎱 General Lounge")),str(item.get("author","Player")),str(item.get("title","Untitled")),str(item.get("body","")),str(item.get("link","")),media.get("file"),media.get("kind"),str(item.get("time",datetime.now(timezone.utc).isoformat()))))
                        for reply in item.get("replies",[]):
                            if isinstance(reply,dict):
                                con.execute("INSERT INTO replies (id,post_id,author,body,created_at) VALUES (?,?,?,?,?)",(uuid4().hex,pid,str(reply.get("author","Player")),str(reply.get("body","")),str(reply.get("time",""))))
                        for author in set(item.get("reactions",[])):
                            con.execute("INSERT OR IGNORE INTO reactions (post_id,author,kind) VALUES (?,?,?)",(pid,str(author),"star"))
            except (OSError,ValueError,TypeError,sqlite3.Error):
                pass
            con.execute("INSERT OR REPLACE INTO lounge_meta VALUES ('v7_import_checked','1')")

def lounge_attachment(upload):
    if upload is None: return None
    allowed={"image/png":"png","image/jpeg":"jpg","image/webp":"webp","image/gif":"gif","video/mp4":"mp4","video/webm":"webm"}
    ext=allowed.get(upload.type)
    if not ext: raise ValueError("Upload a PNG, JPG, WebP, GIF, MP4, or WebM file.")
    data=upload.getvalue()
    if len(data)>12*1024*1024: raise ValueError("Files must be 12 MB or smaller.")
    # Verify basic file signatures instead of trusting only the browser MIME type.
    signatures={"png":data.startswith(b"\x89PNG\r\n\x1a\n"),"jpg":data.startswith(b"\xff\xd8\xff"),
                "gif":data.startswith((b"GIF87a",b"GIF89a")),"webp":data.startswith(b"RIFF") and data[8:12]==b"WEBP",
                "mp4":len(data)>12 and data[4:8]==b"ftyp","webm":data.startswith(b"\x1a\x45\xdf\xa3")}
    if not signatures[ext]: raise ValueError("The file contents don't match its format.")
    LOUNGE_MEDIA.mkdir(exist_ok=True)
    filename=uuid4().hex+"."+ext
    (LOUNGE_MEDIA/filename).write_bytes(data)
    return {"file":filename,"kind":"video" if ext in ("mp4","webm") else "image"}

def lounge_link(value):
    if not value: return ""
    u=urlparse(value.strip())
    if u.scheme not in ("http","https") or not u.hostname or u.username or u.password:
        raise ValueError("Links must be valid public http:// or https:// addresses.")
    return value.strip()

def lounge_publish(room,author,title,body,link,upload,topic,symbol,account_id):
    if not account_id or not active_account() or active_account()["id"] != account_id:
        raise ValueError("Sign in before publishing.")
    if room not in LOUNGE_ROOMS or not title.strip() or len(title.strip()) > 140 or len(body.strip()) > 10000:
        raise ValueError("Invalid room or post length.")
    media=lounge_attachment(upload)
    try:
        with lounge_connection() as con:
            con.execute("INSERT INTO posts (id,room,author,title,body,link,media_file,media_kind,created_at,topic,symbol) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (uuid4().hex,room,author,title.strip(),body.strip(),lounge_link(link),media["file"] if media else None,media["kind"] if media else None,datetime.now(timezone.utc).isoformat(),topic,symbol.strip().upper()[:20]))
            con.execute("UPDATE posts SET account_id=? WHERE rowid=last_insert_rowid()", (account_id,))
    except Exception:
        if media:
            (LOUNGE_MEDIA/media["file"]).unlink(missing_ok=True)
        raise

def lounge_react(pid,author,account_id):
    if not account_id: return
    with lounge_connection() as con:
        found=con.execute("SELECT 1 FROM reactions WHERE post_id=? AND account_id=? AND kind='star'",(pid,account_id)).fetchone()
        if found: con.execute("DELETE FROM reactions WHERE post_id=? AND account_id=? AND kind='star'",(pid,account_id))
        else: con.execute("INSERT INTO reactions (post_id,author,kind,account_id) VALUES (?,?,'star',?)",(pid,author,account_id))

def lounge_delete(pid,account_id):
    if not active_account() or active_account()["id"] != account_id: return False
    with lounge_connection() as con:
        post=con.execute("SELECT media_file FROM posts WHERE id=? AND account_id=?",(pid,account_id)).fetchone()
        if not post: return False
        con.execute("DELETE FROM reactions WHERE post_id=?",(pid,))
        con.execute("DELETE FROM replies WHERE post_id=?",(pid,))
        con.execute("DELETE FROM posts WHERE id=? AND account_id=?",(pid,account_id))
    if post["media_file"] and Path(post["media_file"]).name==post["media_file"]:
        (LOUNGE_MEDIA/post["media_file"]).unlink(missing_ok=True)
    return True


# NOCTIS v10: local community identities, follows, threaded conversations, notifications.
# Local SQLite remains development-only: no internet synchronization or verified identities.
AVATAR_ICONS = ["🎱", "🟢", "🎮", "📈", "₿", "⚡", "🏀", "🌙", "🚀", "🐉", "🃏", "🎯"]

def social_init():
    accounts_init()
    lounge_init()
    with account_db() as con:
        cols = {row[1] for row in con.execute("PRAGMA table_info(accounts)")}
        for name, ddl in {"bio": "TEXT NOT NULL DEFAULT ''", "avatar": "TEXT NOT NULL DEFAULT '🎱'", "favorite_room": "TEXT NOT NULL DEFAULT '🎱 General Lounge'", "profile_visibility": "TEXT NOT NULL DEFAULT 'public'"}.items():
            if name not in cols:
                con.execute(f"ALTER TABLE accounts ADD COLUMN {name} {ddl}")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS follows (
            follower_id TEXT NOT NULL, followed_id TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY (follower_id, followed_id),
            CHECK (follower_id != followed_id));
        CREATE INDEX IF NOT EXISTS follows_target_idx ON follows(followed_id);
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL, actor_id TEXT NOT NULL,
            kind TEXT NOT NULL, post_id TEXT, message TEXT NOT NULL,
            created_at TEXT NOT NULL, read_at TEXT);
        CREATE INDEX IF NOT EXISTS notifications_user_idx ON notifications(account_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS lounge_reports (
            id TEXT PRIMARY KEY, post_id TEXT NOT NULL, reporter_id TEXT NOT NULL,
            reason TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(post_id, reporter_id));
        """)
    with lounge_connection() as con:
        cols = {row[1] for row in con.execute("PRAGMA table_info(replies)")}
        if "parent_reply_id" not in cols:
            con.execute("ALTER TABLE replies ADD COLUMN parent_reply_id TEXT")

def social_profile(account_id):
    if not account_id: return None
    with account_db() as con:
        row = con.execute("SELECT id,username,display_name,bio,avatar,favorite_room,profile_visibility,created_at FROM accounts WHERE id=?",(account_id,)).fetchone()
        if not row: return None
        user = dict(row)
        user["followers"] = con.execute("SELECT COUNT(*) FROM follows WHERE followed_id=?",(account_id,)).fetchone()[0]
        user["following"] = con.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?",(account_id,)).fetchone()[0]
    with lounge_connection() as con:
        user["posts"] = con.execute("SELECT COUNT(*) FROM posts WHERE account_id=?",(account_id,)).fetchone()[0]
    return user

def social_notify(target, actor, kind, message, post_id=None):
    if not target or target == actor: return
    with account_db() as con:
        con.execute("INSERT INTO notifications VALUES (?,?,?,?,?,?,?,NULL)",
            (uuid4().hex,target,actor,kind,post_id,message[:250],datetime.now(timezone.utc).isoformat()))

def social_follow(target_id):
    me=active_account()
    if not me or not target_id or target_id==me["id"]: return
    with account_db() as con:
        if not con.execute("SELECT 1 FROM accounts WHERE id=?", (target_id,)).fetchone(): return
    with account_db() as con:
        exists=con.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?",(me["id"],target_id)).fetchone()
        if exists:
            con.execute("DELETE FROM follows WHERE follower_id=? AND followed_id=?",(me["id"],target_id))
        else:
            con.execute("INSERT INTO follows VALUES (?,?,?)",(me["id"],target_id,datetime.now(timezone.utc).isoformat()))
    if not exists:
        social_notify(target_id,me["id"],"follow",f"@{me['username']} followed your profile")

def social_is_following(target_id):
    me=active_account()
    if not me: return False
    with account_db() as con:
        return bool(con.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?",(me["id"],target_id)).fetchone())

def social_public_profile(account_id):
    person=social_profile(account_id)
    if not person:
        st.info("This is an older unclaimed post, without a registered NOCTIS account.")
        return
    st.markdown(f"### {html.escape(person['avatar'])} {html.escape(person['display_name'])}")
    st.caption("@"+person["username"]+" · Local NOCTIS member")
    if person["profile_visibility"]=="private" and (not active_account() or active_account()["id"]!=account_id):
        st.info("This member has hidden their profile details.")
    else:
        st.write(person["bio"] or "No bio yet.")
        st.caption(f"{person['posts']} posts · {person['followers']} followers · {person['following']} following")
        st.caption("Favorite room: "+person["favorite_room"])
    me=active_account()
    if me and me["id"]!=account_id:
        label="✓ Following · Unfollow" if social_is_following(account_id) else "+ Follow"
        if st.button(label,key="follow_"+account_id):
            social_follow(account_id)
            st.rerun()

def social_profile_editor():
    account=active_account()
    if not account: return
    person=social_profile(account["id"])
    if not person: return
    with st.expander("🎮 EDIT MY COMMUNITY PROFILE",expanded=False):
        with st.form("social_profile_editor_form"):
            display=st.text_input("Gamertag / display name",value=person["display_name"],max_chars=32)
            avatar=st.selectbox("Avatar badge",AVATAR_ICONS,index=AVATAR_ICONS.index(person["avatar"]) if person["avatar"] in AVATAR_ICONS else 0)
            bio=st.text_area("About me",value=person["bio"],max_chars=300,height=95,placeholder="What do you research or collect?")
            room=st.selectbox("Favorite Lounge room",LOUNGE_ROOMS,index=LOUNGE_ROOMS.index(person["favorite_room"]) if person["favorite_room"] in LOUNGE_ROOMS else 0)
            visibility=st.selectbox("Profile details",["public","private"],index=0 if person["profile_visibility"]=="public" else 1,help="Private hides your bio and stats; posts you publish remain visible.")
            if st.form_submit_button("SAVE PROFILE"):
                if len(display.strip())<2 or any(x in display for x in "<>\\"):
                    st.error("Use a display name with 2–32 characters and no markup.")
                else:
                    with account_db() as con:
                        con.execute("UPDATE accounts SET display_name=?,avatar=?,bio=?,favorite_room=?,profile_visibility=? WHERE id=?",(display.strip(),avatar,bio.strip(),room,visibility,account["id"]))
                    st.session_state.noctis_account={**account,"display_name":display.strip()}
                    st.success("Community profile updated.")
                    st.rerun()

def social_notifications():
    me=active_account()
    if not me: return
    with account_db() as con:
        unread=con.execute("SELECT COUNT(*) FROM notifications WHERE account_id=? AND read_at IS NULL",(me["id"],)).fetchone()[0]
        rows=[dict(x) for x in con.execute("SELECT * FROM notifications WHERE account_id=? ORDER BY created_at DESC LIMIT 30",(me["id"],))]
    with st.expander(f"🔔 NOTIFICATIONS · {unread} unread",expanded=False):
        if not rows: st.caption("No notifications yet. Replies, reactions and new followers appear here.")
        for note in rows:
            st.markdown(("**● **" if not note["read_at"] else "")+html.escape(note["message"]))
            st.caption(note["created_at"][:16].replace("T"," ")+" UTC")
        if unread and st.button("Mark all read",key="social_mark_read"):
            with account_db() as con:
                con.execute("UPDATE notifications SET read_at=? WHERE account_id=? AND read_at IS NULL",(datetime.now(timezone.utc).isoformat(),me["id"]))
            st.rerun()

def social_report(post_id):
    me=active_account()
    if not me: return
    with st.popover("⚑ Report"):
        reason=st.selectbox("Reason",["Spam","Harassment","Misleading financial claims","Inappropriate content","Other"],key="report_reason_"+post_id)
        if st.button("Submit report",key="report_submit_"+post_id):
            with account_db() as con:
                try:
                    con.execute("INSERT INTO lounge_reports VALUES (?,?,?,?,?)",(uuid4().hex,post_id,me["id"],reason,datetime.now(timezone.utc).isoformat()))
                    st.success("Report saved for review on this local installation.")
                except sqlite3.IntegrityError:
                    st.info("You've already reported this post.")

def social_reply(post_id,body,parent_reply_id=None):
    me=active_account()
    if not me or not body.strip(): return
    with lounge_connection() as con:
        parent=con.execute("SELECT account_id FROM posts WHERE id=?",(post_id,)).fetchone()
        if not parent: return
        if parent_reply_id:
            parent_reply=con.execute("SELECT id,account_id FROM replies WHERE id=? AND post_id=?",(parent_reply_id,post_id)).fetchone()
            if not parent_reply: return
        con.execute("INSERT INTO replies (id,post_id,author,body,created_at,account_id,parent_reply_id) VALUES (?,?,?,?,?,?,?)",(uuid4().hex,post_id,me["display_name"],body.strip()[:700],datetime.now(timezone.utc).isoformat(),me["id"],parent_reply_id))
        target=parent["account_id"]
        reply_target=parent_reply["account_id"] if parent_reply_id else None
    social_notify(target,me["id"],"reply",f"@{me['username']} replied to your post",post_id)
    if reply_target and reply_target != target:
        social_notify(reply_target,me["id"],"reply",f"@{me['username']} replied to your comment",post_id)

def social_react(post_id):
    me=active_account()
    if not me: return
    with lounge_connection() as con:
        post=con.execute("SELECT account_id FROM posts WHERE id=?",(post_id,)).fetchone()
        if not post: return
        existing=con.execute("SELECT 1 FROM reactions WHERE post_id=? AND account_id=? AND kind='star'",(post_id,me["id"])).fetchone()
        if existing:
            con.execute("DELETE FROM reactions WHERE post_id=? AND account_id=? AND kind='star'",(post_id,me["id"]))
        else:
            con.execute("INSERT INTO reactions (post_id,author,kind,account_id) VALUES (?,?,'star',?)",(post_id,me["display_name"],me["id"]))
    if not existing:
        social_notify(post["account_id"],me["id"],"reaction",f"@{me['username']} reacted to your post",post_id)

social_init()

def lounge_page():
    try:
        configured=bool(cloud_config())
    except ValueError:
        configured=False
    if configured:
        mode=st.radio("Lounge network",["Online Lounge (Supabase DEV)","Local Lounge (SQLite)"],horizontal=True,key="noctis_lounge_network")
        if mode=="Online Lounge (Supabase DEV)":
            cloud_lounge_page()
            return
    st.markdown("""<style>
    .lounge-hero{padding:27px 30px;border:1px solid #4f995e;border-radius:20px;background:radial-gradient(ellipse at 92% 5%,#285e3c,#131f20 55%,#171227);box-shadow:0 8px 35px #0005}
    .lounge-hero h1{color:#e4ffe2;letter-spacing:1.4px;font-size:2.2rem;margin:4px 0}
    .lounge-hero p{color:#b6d5c1;margin:0}
    .lounge-post{padding:19px 22px;margin:16px 0 7px;border:1px solid #355747;border-radius:17px;background:linear-gradient(120deg,#192322,#1b1728);box-shadow:0 8px 20px #0003}
    .lounge-post h3{color:#f1f7f1;margin:10px 0 8px;font-size:1.2rem}
    .lounge-post .author{color:#a5f3a7;font-weight:800}
    .lounge-post .muted{color:#a7b5ae;font-size:.78rem}
    .lounge-pill{display:inline-block;padding:4px 10px;border:1px solid #53895c;border-radius:30px;color:#baf5bd;font-size:.75rem;margin-right:8px}
    </style>""",unsafe_allow_html=True)
    st.markdown("<div class='lounge-hero'><span class='lounge-pill'>✦ NOCTIS SOCIAL</span><span class='lounge-pill'>LOCAL BETA</span><h1>🎱 THE BILLIARDS LOUNGE</h1><p>Pick a room. Pull up a chair. Share what you're watching.</p></div>",unsafe_allow_html=True)
    try:
        lounge_init()
        storage_upgrade_v12()
    except sqlite3.Error as exc:
        st.error(f"Could not open the local Lounge database: {exc}")
        return
    account=active_account()
    active=account["display_name"] if account else "Guest"
    account_id=account["id"] if account else None
    st.caption("Identity: "+active+" · Sign in or out from Home · Shared locally on this computer only")
    if account:
        person=social_profile(account_id)
        if person:
            st.caption(f"{person['avatar']} @{account['username']} · {person['followers']} followers · {person['following']} following")
    with lounge_connection() as con:
        totals={r["room"]:r["n"] for r in con.execute("SELECT room, COUNT(*) AS n FROM posts GROUP BY room")}
    with st.expander("🎮 MEMBER DIRECTORY · FIND PEOPLE", expanded=False):
        member_search=st.text_input("Search local members",key="social_member_search",placeholder="Gamertag or username")
        with account_db() as con:
            members=[dict(r) for r in con.execute("SELECT id,username,display_name,avatar,profile_visibility FROM accounts ORDER BY created_at DESC LIMIT 100")]
        if member_search.strip():
            term=member_search.strip().casefold()
            members=[m for m in members if term in m["username"].casefold() or term in m["display_name"].casefold()]
        st.caption(f"{len(members)} matching local member(s) · This is not an online directory")
        for member in members[:20]:
            with st.expander(member["avatar"]+" "+member["display_name"]+" · @"+member["username"]):
                social_public_profile(member["id"])
    st.markdown("#### CHOOSE A ROOM")
    room_cols=st.columns(3)
    if "lounge_selected_room" not in st.session_state: st.session_state.lounge_selected_room=LOUNGE_ROOMS[0]
    for i,r in enumerate(LOUNGE_ROOMS):
        name,description,emoji=LOUNGE_ROOM_INFO[r]
        with room_cols[i%3]:
            if st.button(f"{emoji}  {name}  ·  {totals.get(r,0)} posts",key="room_btn_"+str(i),use_container_width=True,
                         type="primary" if st.session_state.lounge_selected_room==r else "secondary"):
                st.session_state.lounge_selected_room=r
                st.rerun()
            st.caption(description)
    room=st.session_state.lounge_selected_room
    st.divider()
    st.subheader(LOUNGE_ROOM_INFO[room][0])
    st.caption(LOUNGE_ROOM_INFO[room][1])
    if not account:
        st.info("🔒 Sign in from Home to create posts, reply, or react. Guests can read discussions.")
    with st.expander("✚ CREATE A POST",expanded=False) if account else st.container():
        if account:
          with st.form("lounge_create_v8",clear_on_submit=True):
              topic=st.selectbox("Post type",["Discussion","Question","Market research","Chart / analysis","News / resource","Collection showcase"])
              title=st.text_input("Title",max_chars=110,placeholder="What's on your mind?")
              body=st.text_area("Your post",max_chars=5000,height=140,placeholder="Share your thesis, source, question or collection story...")
              x,y=st.columns(2)
              with x: symbol=st.text_input("Ticker / card / team (optional)",max_chars=20,placeholder="BTC, NVDA, Charizard...")
              with y: link=st.text_input("Link (optional)",placeholder="https://...")
              upload=st.file_uploader("Photo or short video · 12 MB max",type=["png","jpg","jpeg","webp","gif","mp4","webm"])
              if st.form_submit_button("✦ PUBLISH POST",use_container_width=True):
                  if not title.strip() or not body.strip(): st.warning("Add a title and message before posting.")
                  else:
                      try:
                          # Validate the link before saving an attachment.
                          lounge_link(link)
                          lounge_publish(room,active,title,body,link,upload,topic,symbol,account_id)
                          st.rerun()
                      except (OSError,ValueError,sqlite3.Error) as exc: st.error(str(exc))
    filter_cols=st.columns([2,1,1])
    with filter_cols[0]: query=st.text_input("Search posts",placeholder="Search titles, authors, tickers, or text...",key="lounge_search_v8")
    with filter_cols[1]: sort=st.selectbox("Sort",["Newest","Oldest","Most reactions","Most replies"],key="lounge_sort_v8")
    with filter_cols[2]: topic_filter=st.selectbox("Type",["All types","Discussion","Question","Market research","Chart / analysis","News / resource","Collection showcase"],key="lounge_topic_v8")
    followed_only=st.checkbox("Show posts from people I follow",value=False,key="social_followed_only",disabled=not bool(account))
    st.button("↻ Refresh posts",key="lounge_refresh_v8",help="Reloads local discussion posts")
    with lounge_connection() as con:
        posts=[dict(row) for row in con.execute("""SELECT p.*,
            (SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) AS stars,
            (SELECT COUNT(*) FROM replies q WHERE q.post_id=p.id) AS reply_count
            FROM posts p WHERE p.room=?""",(room,))]
    if followed_only and account:
        with account_db() as con:
            followed={r[0] for r in con.execute("SELECT followed_id FROM follows WHERE follower_id=?",(account_id,))}
        posts=[p for p in posts if p.get("account_id") in followed]
    if topic_filter!="All types": posts=[p for p in posts if p["topic"]==topic_filter]
    if query.strip():
        needle=query.strip().casefold()
        posts=[p for p in posts if any(needle in str(p.get(k,"")).casefold() for k in ("title","body","author","symbol","topic"))]
    if sort=="Newest": posts.sort(key=lambda p:p["created_at"],reverse=True)
    elif sort=="Oldest": posts.sort(key=lambda p:p["created_at"])
    elif sort=="Most reactions": posts.sort(key=lambda p:(p["stars"],p["created_at"]),reverse=True)
    else: posts.sort(key=lambda p:(p["reply_count"],p["created_at"]),reverse=True)
    st.caption(f"Showing {min(len(posts),40)} of {len(posts)} matching posts · displaying at most 40 per view")
    if not posts: st.info("No posts match this room and search. Be the first to start a conversation.")
    for post in posts[:40]:
        pid=post["id"]
        stamp=post["created_at"][:16].replace("T"," · ")+" UTC"
        tag=("<span class='lounge-pill'>"+html.escape(post["symbol"])+"</span>") if post["symbol"] else ""
        st.markdown("<div class='lounge-post'><span class='author'>◉ "+html.escape(post["author"])+"</span><span class='muted'> · "+html.escape(stamp)+"</span><div style='margin-top:10px'><span class='lounge-pill'>"+html.escape(post["topic"])+"</span>"+tag+"</div><h3>"+html.escape(post["title"])+"</h3><div style='white-space:pre-wrap;color:#d3e0d6'>"+html.escape(post["body"])+"</div></div>",unsafe_allow_html=True)
        if post.get("account_id"):
            with st.expander("🎮 VIEW @" + post["author"] + "'S PROFILE", expanded=False):
                social_public_profile(post["account_id"])
        if account:
            social_report(pid)
        if post["link"]:
            try:
                safe=lounge_link(post["link"])
                st.link_button("↗ Open shared source",safe)
                if "youtube.com/watch" in safe or "youtu.be/" in safe:
                    with st.expander("▶ Watch linked video"):
                        st.video(safe)
            except ValueError: pass
        fname=post.get("media_file") or ""
        if fname and Path(fname).name==fname:
            media_path=LOUNGE_MEDIA/fname
            if media_path.is_file():
                if post["media_kind"]=="image": st.image(str(media_path),width=440)
                elif post["media_kind"]=="video": st.video(str(media_path))
        c1,c2,c3=st.columns([1,2,3])
        with c1:
            if st.button(f"★ {post['stars']}",key="v8_star_"+pid,help="Sign in to react" if not account else "Toggle reaction", disabled=not bool(account)):
                social_react(pid)
                st.rerun()
        with c2:
            with st.expander(f"💬 {post['reply_count']} replies"):
                with lounge_connection() as con:
                    replies=[dict(r) for r in con.execute("SELECT * FROM replies WHERE post_id=? ORDER BY created_at ASC",(pid,))]
                roots=[r for r in replies if not r.get("parent_reply_id") or r.get("parent_reply_id") not in {x["id"] for x in replies}]
                children={}
                for r in replies:
                    if r.get("parent_reply_id"):
                        children.setdefault(r["parent_reply_id"],[]).append(r)
                for root in roots[:80]:
                    st.markdown("**"+html.escape(root["author"])+"** · "+html.escape(root["body"]))
                    for child in children.get(root["id"],[])[:20]:
                        st.markdown("　↳ **"+html.escape(child["author"])+"** · "+html.escape(child["body"]))
                    if account:
                        with st.popover("↳ Reply to "+root["author"],use_container_width=False):
                            with st.form("nested_"+root["id"],clear_on_submit=True):
                                nested=st.text_input("Your reply",max_chars=700)
                                if st.form_submit_button("SEND REPLY") and nested.strip():
                                    social_reply(pid,nested,root["id"])
                                    st.rerun()
                if account:
                  with st.form("v8_reply_"+pid,clear_on_submit=True):
                      reply=st.text_input("Write a reply",max_chars=700,key="v8_replytext_"+pid)
                      if st.form_submit_button("SEND") and reply.strip():
                          social_reply(pid,reply)
                          st.rerun()
        with c3:
            if account_id and post.get("account_id")==account_id:
                with st.popover("⋯ My post"):
                    if st.button("Delete post",key="v8_delete_"+pid):
                        lounge_delete(pid,account_id)
                        st.rerun()
    st.divider()
    with st.expander("ABOUT THIS LOUNGE · SAFETY & PRIVACY"):
        st.write("This is a local prototype with password-protected local accounts. Accounts are NOT secure public internet identities, and users with access to the computer/database can access local data. Posts and reports stay on this computer. There is no active moderation, email recovery, cross-device sync, cloud backup, or live chat. Do not share personal financial information; research and predictions are not verified advice.")

def noctis_open_settings():
    st.session_state.noctis_show_settings=True
    st.session_state.noctis_show_profile=False
    st.session_state.noctis_show_home=False
    st.session_state.noctis_show_lounge=False

def noctis_open_profile():
    st.session_state.noctis_show_settings=False
    st.session_state.noctis_show_profile=True
    st.session_state.noctis_show_home=False
    st.session_state.noctis_show_lounge=False

# Home owns the market switcher; the sidebar only displays navigation for the chosen market.
if "noctis_market_space" not in st.session_state:
    st.session_state.noctis_market_space = "📈 Trading & Crypto"
market_space = st.session_state.noctis_market_space
page = "Home"
st.markdown("""<style>
[data-testid="stSidebar"] .stButton button{min-height:43px!important;border-radius:12px!important;margin:3px 0!important}
[data-testid="stSidebar"] [role="radiogroup"] label{padding:8px 10px!important;margin:3px 0!important;border-radius:10px!important}
[data-testid="stSidebar"] [data-testid="stSelectbox"]{margin:8px 0!important}
.v25-market-guide{background:linear-gradient(120deg,#1e182b,#111c22);border:1px solid #56476a;border-radius:15px;padding:17px 20px;margin:14px 0 19px}
.v25-market-guide strong{color:#d8c0ff;letter-spacing:.07em}
.v25-market-guide p{color:#b8c3cd;margin:7px 0 0;font-size:13px}
.st-key-v24_community_nav [data-testid="stSegmentedControl"] button{min-height:55px!important;border-radius:14px!important;font-weight:750!important;border:1px solid #467352!important;margin:3px!important;padding:10px 15px!important}
.st-key-v24_community_nav [data-testid="stSegmentedControl"]{gap:8px!important;flex-wrap:wrap!important}
</style>""",unsafe_allow_html=True)
with st.sidebar:
    st.title("✦ NOCTIS")
    st.caption("MULTI-MARKET INTELLIGENCE")
    st.divider()
    account = active_account()
    st.caption("◉ " + ("@" + account["username"] if account else "GUEST"))
    st.divider()
    # Navigation: Command Center and My Profile are floating workspace actions.
    with st.popover("◈ CHOOSE MARKET ▾", use_container_width=True):
        st.button("📈 Trading & Crypto", key="v23_choose_trading", use_container_width=True,
                  on_click=choose_market, args=("📈 Trading & Crypto",))
        st.button("⚡ Alternative Markets", key="v23_choose_alternative", use_container_width=True,
                  on_click=choose_market, args=("⚡ Alternative Markets",))
    st.button("🎱 THE BILLIARDS LOUNGE", key="sidebar_lounge", use_container_width=True, on_click=noctis_open_lounge)
    st.button("⚙ SETTINGS", key="v23_sidebar_settings", use_container_width=True, on_click=noctis_open_settings)
    if not st.session_state.get("noctis_show_home", True) and not st.session_state.get("noctis_show_lounge", False) and not st.session_state.get("noctis_show_profile",False) and not st.session_state.get("noctis_show_settings",False):
        st.caption("MARKET WORKSPACE")
        if market_space == "📈 Trading & Crypto":
            stock_group = st.selectbox(
                "TRADING WORKSPACE", ["📊 Market Terminal", "✦ NOCTIS Info", "★ My Watchlist"],
                key="noctis_stock_group")
            if stock_group == "📊 Market Terminal":
                page = st.radio("STOCKS & CRYPTO", ["Trading Terminal", "Crypto Terminal", "Technical Analysis", "Market Volume", "Stock Research"], key="noctis_stock_navigation")
                st.caption("Market research · delayed daily quotes")
            elif stock_group == "★ My Watchlist":
                page = "My Watchlist"
                st.caption("Personal lists · notes · targets · asset research")
            else:
                page = st.radio("NOCTIS INFO", ["Info Home", "Stocks for Beginners", "Trading & Crypto Academy", "Market Videos & Live", "Trader Forums", "Research Library", "Trading Calculators"], key="noctis_info_navigation")
                st.caption("Learn • research • community • videos")
        else:
            st.markdown("<div class='alt-sidebar-tag'>✦ COLLECTIBLES / SPORTS / GAMING</div>", unsafe_allow_html=True)
            page = st.radio("ALTERNATIVE MARKETS", ["Alternative Market Overview", "Pokémon Card Market", "Pokémon Community", "Sportsbook & Prediction Research", "Sports & Prediction Forums", "Gambling Site Research", "Gambling Research Forums"], key="noctis_alt_navigation")
            st.caption("Public information · no wagering")
        st.divider()
        st.caption("LOCAL TEST  •  INFORMATION ONLY")
if st.session_state.get("noctis_show_settings",False):
    page = "Settings"
elif st.session_state.get("noctis_show_profile",False):
    page = "My Profile"
elif st.session_state.get("noctis_show_lounge", False):
    page = "Billiards Lounge"
elif st.session_state.get("noctis_show_home", True):
    page = "Home"

@st.cache_data(ttl=900, show_spinner=False)
def fetch_market_history(ticker):
    data = yf.Ticker(ticker).history(period="2y", interval="1d", auto_adjust=True)
    if data.empty:
        raise ValueError("No market data returned for this symbol.")
    data = data.dropna(subset=["Open", "High", "Low", "Close"])
    return data


def evaluate_forecast(data):
    # Train only on earlier observations; test on later observations.
    close = data["Close"].astype(float).reset_index(drop=True)
    returns = close.pct_change()
    features = pd.DataFrame({
        "return_1": returns,
        "return_2": returns.shift(1),
        "return_3": returns.shift(2),
        "mean_5": returns.rolling(5).mean(),
        "mean_20": returns.rolling(20).mean(),
        "volatility_10": returns.rolling(10).std(),
    })
    # Target is next trading day's percentage return.
    target = returns.shift(-1).rename("target")
    dataset = features.join(target).dropna()
    if len(dataset) < 100:
        return None
    x = dataset.drop(columns=["target"])
    y = dataset["target"]
    split = int(len(dataset) * 0.8)
    model = RandomForestRegressor(n_estimators=80, max_depth=5, min_samples_leaf=5, random_state=42, n_jobs=1)
    model.fit(x.iloc[:split], y.iloc[:split])
    predictions = model.predict(x.iloc[split:])
    actual = y.iloc[split:].to_numpy()
    mae = float(abs(predictions - actual).mean() * 100)
    directional = float(((predictions > 0) == (actual > 0)).mean() * 100)
    # Latest features are not part of the labeled dataset because tomorrow is unknown.
    newest = features.dropna().iloc[[-1]]
    next_prediction = float(model.predict(newest)[0] * 100)
    comparison = pd.DataFrame({
        "Actual next-day change (%)": actual * 100,
        "Predicted next-day change (%)": predictions * 100,
    })
    return mae, directional, next_prediction, comparison


def trader_community(ticker, company):
    st.subheader("STOCK DISCUSSION HUB")
    st.caption("Jump directly to conversations and trading ideas for your selected asset. External websites open in a new tab.")

    selected = st.text_input("Stock or crypto ticker", value=ticker, key=f"discussion_symbol_{ticker}").strip().upper()
    if not selected:
        st.info("Enter a ticker symbol to find discussions.")
        return
    if not re.fullmatch(r"[A-Z0-9.^=-]{1,18}", selected):
        st.warning("Use a ticker symbol such as NVDA, AAPL, TSLA, SPY, or BTC-USD.")
        return

    # Match the naming conventions of each destination.
    stocktwits_symbol = "BTC.X" if selected in ("BTC", "BTC-USD") else selected
    reddit_term = "BTC" if selected == "BTC-USD" else selected
    tv_exchange = {
        "AAPL": "NASDAQ", "MSFT": "NASDAQ", "NVDA": "NASDAQ", "TSLA": "NASDAQ",
        "SPY": "AMEX", "BTC": "BITSTAMP", "BTC-USD": "BITSTAMP",
    }.get(selected)
    tv_symbol = "BTCUSD" if selected in ("BTC", "BTC-USD") else selected

    st.markdown(f"### Discussions for ${selected}")
    st.caption("These links lead to the platforms themselves. They are not scraped posts or verified trading recommendations.")
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown("#### Stocktwits")
            st.write("Trader posts and market sentiment for this symbol.")
            st.link_button("Open stock discussion ↗", f"https://stocktwits.com/symbol/{stocktwits_symbol}", use_container_width=True)
        with st.container(border=True):
            st.markdown("#### Reddit")
            st.write("Find posts mentioning this ticker across Reddit communities.")
            st.link_button("Search Reddit discussions ↗", "https://www.reddit.com/search/?" + urlencode({"q": reddit_term + " stock", "sort": "new"}), use_container_width=True)
            st.link_button("Search r/stocks ↗", "https://www.reddit.com/r/stocks/search/?" + urlencode({"q": reddit_term, "restrict_sr": "1", "sort": "new"}), use_container_width=True)
    with right:
        with st.container(border=True):
            st.markdown("#### TradingView")
            st.write("Chart-based ideas and analysis posted by traders.")
            if tv_exchange:
                tv_url = f"https://www.tradingview.com/symbols/{tv_exchange}-{tv_symbol}/ideas/"
                st.link_button("Open trading ideas ↗", tv_url, use_container_width=True)
            else:
                st.link_button("Find ticker on TradingView ↗", "https://www.tradingview.com/search/?" + urlencode({"query": tv_symbol}), use_container_width=True)
        with st.container(border=True):
            st.markdown("#### r/wallstreetbets")
            st.write("Search speculative trades, options talk, and ticker discussions.")
            st.link_button("Search r/wallstreetbets ↗", "https://www.reddit.com/r/wallstreetbets/search/?" + urlencode({"q": reddit_term, "restrict_sr": "1", "sort": "new"}), use_container_width=True)

    st.info("Posts are opinions, not verified forecasts. Some platforms may require you to sign in to view or participate.")


# Pins are saved only on this computer, next to analytics.py.
PINS_FILE = Path(__file__).resolve().with_name("noctis_watchlist.json")


def load_pins():
    try:
        values = json_storage.loads(PINS_FILE.read_text(encoding="utf-8"))
        if isinstance(values, list):
            return [v for v in values if isinstance(v, str) and re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", v)]
    except (OSError, ValueError, TypeError):
        pass
    return []


def save_pins(values):
    try:
        PINS_FILE.write_text(json_storage.dumps(list(dict.fromkeys(values)), indent=2), encoding="utf-8")
    except OSError as exc:
        st.error(f"Couldn't save the watchlist locally: {exc}")


MARKET_GROUPS = {
    "Technology & AI": "AAPL MSFT NVDA AMD GOOGL GOOG AMZN META AVGO ORCL CRM ADBE INTC MU QCOM TXN AMAT LRCX KLAC SNOW PLTR NET CRWD PANW NOW IBM DELL HPE SHOP UBER ABNB SPOT NFLX RBLX DDOG MDB ARM SMCI".split(),
    "Finance & Payments": "JPM BAC WFC C GS MS CITI V MA AXP PYPL SQ COIN HOOD SCHW BLK BX KKR USB PNC TFC SOFI".split(),
    "Consumer & Retail": "TSLA WMT COST TGT HD LOW NKE SBUX MCD CMG KO PEP PG ULTA LULU DIS ROKU F GM RIVN LCID BABA PDD".split(),
    "Healthcare & Pharma": "LLY UNH JNJ ABBV MRK PFE AMGN GILD ISRG TMO DHR ABT BMY CVS CI HUM NVO REGN VRTX".split(),
    "Energy & Industry": "XOM CVX COP OXY SLB EOG VLO CAT DE GE GEHC BA LMT RTX NOC UPS FDX UNP HON MMM".split(),
    "ETFs & Indices": "SPY QQQ VOO VTI DIA IWM XLK XLF XLE XLV XLY XLI XLP XLU XLB SMH SOXX ARKK SCHD VIG VYM GLD SLV TLT HYG EEM EFA".split(),
    "Crypto": "BTC-USD ETH-USD SOL-USD XRP-USD ADA-USD DOGE-USD AVAX-USD LINK-USD LTC-USD BCH-USD".split(),
}

@st.cache_data(ttl=900, show_spinner=False)
def market_board_quotes(symbols):
    # Fetch only the visible page, not the entire market on each rerun.
    out = []
    for sym in symbols:
        try:
            hist = yf.Ticker(sym).history(period="5d", interval="1d", auto_adjust=True)
            if len(hist) < 2:
                continue
            last = float(hist["Close"].iloc[-1]); prev = float(hist["Close"].iloc[-2])
            out.append({"Symbol": sym, "Last ($)": round(last, 2), "Change (%)": round((last / prev - 1) * 100, 2), "Volume": int(hist["Volume"].iloc[-1]) if "Volume" in hist else 0, "As of": str(hist.index[-1].date())})
        except Exception:
            continue
    return out


def v33_open_intelligence(symbol):
    """Carry a discovered asset into the single-asset research workspace."""
    st.session_state.v33_terminal_view="🧠 Intelligence Lab"
    st.session_state.v32_asset_custom=symbol
    st.session_state.terminal_research_symbol=symbol
    st.rerun()


def market_overview():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / DISCOVERY DESK</div><div class="terminal-title">THE MARKET <span>AT A GLANCE</span></div><div class="terminal-sub">Find movement first. Investigate the evidence in Intelligence Lab.</div></div>', unsafe_allow_html=True)
    all_symbols=list(dict.fromkeys(sym for group in MARKET_GROUPS.values() for sym in group))
    st.caption("Curated market directory · Yahoo Finance daily candles · NOT streaming prices, complete exchange coverage, or live sector performance")
    group=st.selectbox("MARKET CATEGORY",list(MARKET_GROUPS),key="market_category")
    symbols=MARKET_GROUPS[group]
    page_count=(len(symbols)+11)//12
    page_num=st.number_input("DIRECTORY PAGE",min_value=1,max_value=page_count,value=1,step=1,key=f"market_page_{group}")
    visible=symbols[(page_num-1)*12:page_num*12]
    with st.spinner("Checking the selected market page..."):
        rows=market_board_quotes(tuple(visible))
    pinned=load_pins()
    top=st.columns(4)
    top[0].metric("DIRECTORY ASSETS",len(all_symbols))
    top[1].metric("CATEGORIES",len(MARKET_GROUPS))
    top[2].metric("PINNED ASSETS",len(pinned))
    top[3].metric("QUOTES RETURNED",f"{len(rows)} / {len(visible)}")
    st.markdown("#### ◈ SESSION DISCOVERY")
    if rows:
        frame=pd.DataFrame(rows)
        winners=frame.sort_values("Change (%)",ascending=False)
        gainers=winners.head(3)
        decliners=winners.tail(3).sort_values("Change (%)")
        active=frame.sort_values("Volume",ascending=False).head(3)
        gain_col,drop_col,vol_col=st.columns(3)
        for column,title,subset,metric in [(gain_col,"▲ Strongest movers",gainers,"Change (%)"),(drop_col,"▼ Weakest movers",decliners,"Change (%)"),(vol_col,"◈ Highest reported volume",active,"Volume")]:
            with column:
                with st.container(border=True):
                    st.markdown("**"+title+"**")
                    for _,r in subset.iterrows():
                        value=(f"{r[metric]:+.2f}%" if metric=="Change (%)" else f"{int(r[metric]):,}")
                        st.caption(f"{r['Symbol']}  ·  {value}")
        advancing=int((frame["Change (%)"]>0).sum())
        declining=int((frame["Change (%)"]<0).sum())
        flat=int((frame["Change (%)"]==0).sum())
        st.markdown("#### ◈ CATEGORY BREADTH")
        breadth=st.columns(3)
        breadth[0].metric("ADVANCING",advancing)
        breadth[1].metric("DECLINING",declining)
        breadth[2].metric("UNCHANGED",flat)
        st.caption(f"Breadth and movers describe only the {len(rows)} assets returned on this directory page, not the whole {group} sector. As-of dates vary by instrument; inspect the table below.")
        st.markdown("#### ◈ DISCOVERY BOARD")
        st.dataframe(frame.sort_values("Change (%)",ascending=False),use_container_width=True,hide_index=True)
    else:
        st.warning("No provider quotes available for this page. Directory navigation and research shortcuts remain accessible.")
    st.markdown("#### ◈ RESEARCH SHORTCUTS")
    st.caption("Analyze opens the selected symbol directly in Intelligence Lab. Pins use your existing local watchlist.")
    for sym in visible:
        left,middle,right=st.columns([3,1,1],vertical_alignment="center")
        left.markdown(f"**{sym}**")
        if middle.button("★ Pinned" if sym in pinned else "☆ Pin",key=f"board_pin_{sym}",disabled=sym in pinned,use_container_width=True):
            save_pins(pinned+[sym]); st.rerun()
        if right.button("Analyze →",key=f"board_open_{sym}",use_container_width=True):
            v33_open_intelligence(sym)
    st.caption("For detailed chart analysis, signal evidence, and historical evaluation, use Intelligence Lab. Research only; no trading execution.")


@st.cache_data(ttl=3600, show_spinner=False)
def search_assets(query):
    """Best-effort Yahoo Finance public symbol lookup, with a local fallback."""
    catalog = {
        "AAPL": "Apple", "MSFT": "Microsoft", "NVDA": "NVIDIA", "GOOGL": "Alphabet Google",
        "AMZN": "Amazon", "META": "Meta Platforms", "TSLA": "Tesla", "AMD": "Advanced Micro Devices",
        "INTC": "Intel", "NFLX": "Netflix", "PLTR": "Palantir", "COIN": "Coinbase",
        "HOOD": "Robinhood", "JPM": "JPMorgan Chase", "BAC": "Bank of America", "WMT": "Walmart",
        "COST": "Costco", "DIS": "Walt Disney", "KO": "Coca-Cola", "PEP": "PepsiCo",
        "NKE": "Nike", "BA": "Boeing", "F": "Ford", "GM": "General Motors",
        "V": "Visa", "MA": "Mastercard", "PYPL": "PayPal", "UBER": "Uber",
        "SPY": "S&P 500 ETF", "QQQ": "Nasdaq 100 ETF", "VOO": "Vanguard S&P 500 ETF",
        "VTI": "Vanguard Total Market ETF", "IWM": "Russell 2000 ETF", "DIA": "Dow Jones ETF",
        "SCHD": "Schwab Dividend ETF", "GLD": "Gold ETF", "SLV": "Silver ETF",
        "BTC-USD": "Bitcoin", "ETH-USD": "Ethereum", "SOL-USD": "Solana",
    }
    q = query.strip().lower()
    matches = [(k, v) for k, v in catalog.items() if q in k.lower() or q in v.lower()]
    if len(q) >= 2:
        try:
            endpoint = "https://query1.finance.yahoo.com/v1/finance/search?" + urlencode({"q": query, "quotesCount": 20, "newsCount": 0})
            req = Request(endpoint, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=5) as response:
                payload = json.loads(response.read(150000))
            for item in payload.get("quotes", []):
                symbol = str(item.get("symbol", "")).upper()
                label = str(item.get("shortname") or item.get("longname") or symbol)
                if re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", symbol) and (symbol, label) not in matches:
                    matches.append((symbol, label))
        except Exception:
            pass
    unique = {}
    for symbol, label in matches:
        unique.setdefault(symbol, label)
    return list(unique.items())[:35]


def asset_detail(sym):
    try:
        hist = fetch_market_history(sym)
    except Exception as exc:
        st.warning(f"Market history unavailable for {sym}: {str(exc)[:100]}")
        return
    close = hist["Close"].astype(float)
    last = float(close.iloc[-1])
    previous = float(close.iloc[-2]) if len(close) > 1 else last
    st.markdown(f"### {sym} / ASSET INTELLIGENCE")
    st.caption(f"Last available daily candle: {hist.index[-1].strftime('%Y-%m-%d')} • Delayed data, not a live quote")
    a, b, c, d = st.columns(4)
    a.metric("LAST CLOSE", f"${last:,.2f}", f"{(last / previous - 1) * 100:+.2f}%")
    b.metric("52-WEEK HIGH", f"${hist['High'].tail(252).max():,.2f}")
    c.metric("52-WEEK LOW", f"${hist['Low'].tail(252).min():,.2f}")
    d.metric("30-DAY CHANGE", f"{(last / float(close.iloc[-min(31,len(close))]) - 1) * 100:+.2f}%")
    fig = go.Figure(go.Candlestick(x=hist.tail(130).index, open=hist['Open'].tail(130), high=hist['High'].tail(130), low=hist['Low'].tail(130), close=hist['Close'].tail(130), increasing_line_color="#c68cff", decreasing_line_color="#777777", increasing_fillcolor="#b36dff", decreasing_fillcolor="#4b4b4b"))
    fig.update_layout(height=420, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#eeeeee"), xaxis_rangeslider_visible=False, xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#333333"), margin=dict(l=5,r=5,t=10,b=10))
    st.plotly_chart(fig, use_container_width=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("20-SESSION AVERAGE", f"${close.tail(20).mean():,.2f}")
    c2.metric("50-SESSION AVERAGE", f"${close.tail(50).mean():,.2f}")
    c3.metric("LATEST VOLUME", f"{int(hist['Volume'].iloc[-1]):,}" if 'Volume' in hist else "N/A")
    st.caption("Statistics are computed from available daily historical candles. Adjusted prices may differ from exchange quotes.")


# v34 watchlist metadata is separate from the existing ticker list for backwards compatibility.
WATCH_META_FILE = Path(__file__).resolve().with_name("noctis_watchlist_details.json")

def watch_meta_load():
    try:
        obj = json_storage.loads(WATCH_META_FILE.read_text(encoding="utf-8"))
        if isinstance(obj, dict):
            return {str(k):v for k,v in obj.items() if isinstance(v,dict)}
    except (OSError, ValueError, TypeError):
        pass
    return {}

def watch_meta_save(data):
    """Atomic local metadata write; do not modify original watchlist pins."""
    try:
        temporary=WATCH_META_FILE.with_suffix(".tmp")
        temporary.write_text(json_storage.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")
        temporary.replace(WATCH_META_FILE)
        return True
    except OSError as exc:
        st.error("Could not save watchlist details: "+str(exc))
        return False

def watchlist_page():
    """v35: graphic-first watchlist. Existing ticker pins and metadata remain unchanged."""
    st.markdown("""<style>
    .v35-head{padding:16px 22px 17px;border-radius:18px;border:1px solid #62547e;background:linear-gradient(110deg,#1a1727,#111821);margin-bottom:13px}
    .v35-kicker{font-size:11px;letter-spacing:.16em;color:#c6b3e5;font-weight:700}
    .v35-title{font-size:clamp(1.5rem,3vw,2.1rem);font-weight:850;letter-spacing:.03em;color:#f4f1ff;margin:4px 0}
    .v35-sub{font-size:12px;color:#b7b1c6}
    .v35-symbol{font-size:1.35rem;font-weight:850;letter-spacing:.025em;color:#f5f1ff}
    .v35-price{font-size:1.6rem;font-weight:750;line-height:1.15;color:#f7f4ff}
    .v35-tag{font-size:11px;color:#bcb6cb;letter-spacing:.02em}
    .v35-up{color:#57d6a0;font-weight:750}.v35-down{color:#f18496;font-weight:750}
    .v35-noquote{color:#a9a3b8;font-size:12px}
    .st-key-v35_cards [data-testid='stVerticalBlockBorderWrapper']{border-radius:17px!important}
    </style>""",unsafe_allow_html=True)
    st.markdown('<div class="v35-head"><div class="v35-kicker">✦ NOCTIS / PERSONAL MARKETS</div><div class="v35-title">★ MY WATCHLIST</div><div class="v35-sub">Market performance at a glance · Expand any asset for charts, targets and personal notes</div></div>',unsafe_allow_html=True)
    pinned=load_pins()
    metadata=watch_meta_load()
    st.caption('Yahoo Finance daily historical data · Prices are not live quotes · Saved locally on this computer')
    if not pinned:
        st.info('No assets tracked yet. Add your first stock, ETF or crypto symbol below.')
    k1,k2,k3=st.columns(3)
    k1.metric('ASSETS',len(pinned))
    k2.metric('HIGH PRIORITY',sum(metadata.get(x,{}).get('priority')=='High' for x in pinned))
    k3.metric('PERSONAL NOTES',sum(bool(str(metadata.get(x,{}).get('notes','')).strip()) for x in pinned))
    with st.expander('＋ ADD AN ASSET',expanded=not bool(pinned)):
        with st.form('v35_add_asset'):
            symbol_input=st.text_input('Stock, ETF or crypto ticker',placeholder='NVDA, SPY, BTC-USD').strip().upper()
            submitted=st.form_submit_button('ADD TO WATCHLIST')
        if submitted:
            if not re.fullmatch(r'[A-Z0-9.^=\-]{1,20}',symbol_input):
                st.error('Enter a valid symbol (letters, digits, dot, caret or hyphen).')
            elif symbol_input in pinned:
                st.info('That asset is already on your watchlist.')
            else:
                save_pins(pinned+[symbol_input]);st.rerun()
    if not pinned:return
    f1,f2,f3=st.columns([2,1,1])
    with f1: search=st.text_input('Search assets',placeholder='Find ticker, tag or note',key='v35_search').strip().casefold()
    with f2:
        categories=['All categories']+sorted({str(metadata.get(x,{}).get('category','General')) for x in pinned})
        selected_category=st.selectbox('Category',categories,key='v35_filter_category')
    with f3:
        sort=st.selectbox('Sort', ['Custom order','Biggest daily move','High priority','Ticker A–Z'],key='v35_sort')
    assets=[sym for sym in pinned if (selected_category=='All categories' or metadata.get(sym,{}).get('category','General')==selected_category) and (not search or search in (' '.join([sym,str(metadata.get(sym,{}).get('category','General')),str(metadata.get(sym,{}).get('tag','')),str(metadata.get(sym,{}).get('notes',''))])).casefold())]
    quotes={}
    with st.spinner('Loading chart snapshots…'):
        for sym in assets:
            try:
                h=fetch_market_history(sym)
                close=h['Close'].dropna()
                if len(close)<2:raise ValueError('Insufficient price history')
                last=float(close.iloc[-1]);prior=float(close.iloc[-2]);change=(last/prior-1)*100 if prior else 0.0
                quotes[sym]={'history':h,'last':last,'change':change,'date':str(close.index[-1].date()),'series':close.tail(30)}
            except Exception:
                quotes[sym]=None
    if sort=='Ticker A–Z':assets.sort()
    elif sort=='High priority':assets.sort(key=lambda x:({'High':0,'Medium':1,'Low':2}.get(metadata.get(x,{}).get('priority','Medium'),1),x))
    elif sort=='Biggest daily move':assets.sort(key=lambda x:abs(quotes[x]['change']) if quotes[x] else -1,reverse=True)
    st.caption(f'{len(assets)} of {len(pinned)} assets · 30-session mini charts · Select DETAILS to open full analysis')
    if not assets:st.info('No assets match those filters.');return
    for offset in range(0,len(assets),2):
        cols=st.columns(2,gap='medium')
        for col,sym in zip(cols,assets[offset:offset+2]):
            with col:
                meta=metadata.get(sym,{})
                q=quotes[sym]
                with st.container(border=True):
                    name,priority=st.columns([3,1],vertical_alignment='center')
                    with name:st.markdown(f'<div class="v35-symbol">{html.escape(sym)}</div>',unsafe_allow_html=True)
                    with priority:st.caption(str(meta.get('priority','Medium')).upper())
                    st.markdown('<div class="v35-tag">'+html.escape(str(meta.get('category','General')))+((' · #'+html.escape(str(meta.get('tag')))) if meta.get('tag') else '')+'</div>',unsafe_allow_html=True)
                    if q:
                        change=q['change'];direction='v35-up' if change>=0 else 'v35-down'
                        st.markdown(f'<div class="v35-price">${q["last"]:,.2f} <span class="{direction}" style="font-size:14px">{change:+.2f}%</span></div>',unsafe_allow_html=True)
                        import plotly.graph_objects as _go
                        fig=_go.Figure()
                        fig.add_trace(_go.Scatter(x=list(range(len(q['series']))),y=q['series'].tolist(),mode='lines',line={'color':'#52d7a4' if change>=0 else '#f08199','width':2.5},hovertemplate='$%{y:,.2f}<extra></extra>',fill='tozeroy',fillcolor='rgba(82,215,164,0.07)' if change>=0 else 'rgba(240,129,153,0.07)'))
                        fig.update_layout(height=105,margin=dict(l=0,r=0,t=3,b=0),paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)',showlegend=False,xaxis=dict(visible=False),yaxis=dict(visible=False,range=[float(q['series'].min())*.98,float(q['series'].max())*1.02]),dragmode=False)
                        st.plotly_chart(fig,use_container_width=True,config={'displayModeBar':False,'scrollZoom':False},key='v35_spark_'+sym)
                        st.caption('Latest daily close · '+q['date'])
                    else:
                        st.markdown('<div class="v35-noquote">Price chart unavailable · Saved information is still accessible</div>',unsafe_allow_html=True)
                    target=meta.get('target')
                    if target:
                        try:
                            if float(target)>0:st.caption('◎ Reference target $'+f'{float(target):,.2f}')
                        except (TypeError,ValueError):pass
                    if meta.get('notes'):st.caption('✎ '+str(meta['notes'])[:75]+('…' if len(str(meta['notes']))>75 else ''))
                    with st.expander('▾ DETAILS · CHART & PERSONALIZE',expanded=False):
                        if q:
                            period=st.select_slider('Chart window',options=['1mo','3mo','6mo','1y','2y'],value='3mo',key='v35_period_'+sym)
                            n={'1mo':22,'3mo':65,'6mo':130,'1y':260,'2y':520}[period]
                            subset=q['history'].tail(n)
                            chart=_go.Figure(data=[_go.Candlestick(x=subset.index,open=subset['Open'],high=subset['High'],low=subset['Low'],close=subset['Close'],increasing_line_color='#52d7a4',decreasing_line_color='#f08199')])
                            chart.update_layout(height=235,margin=dict(l=2,r=2,t=5,b=2),paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)',xaxis_rangeslider_visible=False,showlegend=False,font={'color':'#c5bdd6'},xaxis={'gridcolor':'#383140'},yaxis={'gridcolor':'#383140'})
                            st.plotly_chart(chart,use_container_width=True,config={'displayModeBar':False},key='v35_candle_'+sym)
                        if st.button('OPEN IN INTELLIGENCE LAB ↗',key='v35_research_'+sym,use_container_width=True):
                            st.session_state.v32_asset_custom=sym
                            st.session_state.v33_terminal_view='🧠 Intelligence Lab'
                            noctis_go_to('📈 Trading & Crypto','📊 Market Terminal','Trading Terminal')
                            st.rerun()
                        with st.form('v35_meta_'+sym):
                            category_options=['General','Long-term','Short-term','Crypto','ETFs','Earnings','Ideas','On hold']
                            priority_options=['High','Medium','Low']
                            a,b=st.columns(2)
                            with a:
                                current_category=str(meta.get('category','General'))
                                cat=st.selectbox('Category',category_options,index=category_options.index(current_category) if current_category in category_options else 0,key='v35_cat_'+sym)
                                priority=st.selectbox('Priority',priority_options,index=priority_options.index(meta.get('priority','Medium')) if meta.get('priority','Medium') in priority_options else 1,key='v35_priority_'+sym)
                            with b:
                                tag=st.text_input('Tag',value=str(meta.get('tag','')),max_chars=32,key='v35_tag_'+sym)
                                try:target_initial=float(meta.get('target') or 0)
                                except (TypeError,ValueError):target_initial=0.0
                                target_price=st.number_input('Reference price ($)',min_value=0.0,max_value=1000000000.0,value=max(0.0,min(target_initial,1000000000.0)),format='%.2f',key='v35_target_'+sym)
                            notes=st.text_area('Personal notes / investment thesis',value=str(meta.get('notes','')),max_chars=2000,height=85,key='v35_notes_'+sym)
                            if st.form_submit_button('SAVE PERSONALIZATION',use_container_width=True):
                                metadata[sym]={'category':cat,'priority':priority,'tag':tag.strip(),'target':float(target_price) if target_price>0 else None,'notes':notes.strip(),'updated_at':datetime.now(timezone.utc).isoformat()}
                                if watch_meta_save(metadata):st.rerun()
                        if st.button('REMOVE FROM WATCHLIST',key='v35_remove_'+sym,use_container_width=True):
                            save_pins([x for x in pinned if x!=sym]);st.rerun()
    st.caption('Charts use cached historical daily candles. Reference targets are not automatic alerts; this is not a brokerage account.')

def beginner_guide():
    st.markdown('<div class="beginner-hero"><div class="beginner-kicker">NOCTIS LEARNING ACADEMY</div><div class="beginner-title">STOCKS FOR BEGINNERS</div><div class="beginner-sub">Learn how markets work before you put real money at risk.</div></div>', unsafe_allow_html=True)
    st.warning("IMPORTANT: Stock prices can fall and you can lose your entire investment. Nothing here guarantees a return.")
    lessons = [
        ("01 / What exactly is a stock?", "Buying a share means owning a small part of a business. Prices move as investors change what they're willing to pay. You can benefit from price appreciation and, for some companies, dividends—but neither is guaranteed.", "Try this: Find a company you know, look up its ticker, and compare its price today with a year ago."),
        ("02 / Exchanges, tickers and trading hours", "Public shares trade on exchanges such as the NYSE and Nasdaq. Each listing has a ticker, such as AAPL. Regular US stock-market hours are generally 9:30 a.m. to 4:00 p.m. Eastern on trading days. Extended-hours prices can be less liquid and more volatile.", "Try this: Look at a daily candle and identify the opening and closing prices."),
        ("03 / Stocks, ETFs and index funds", "A single stock concentrates risk in one company. An exchange-traded fund (ETF) can hold many stocks or other assets. Broad-market index funds seek to track an index; diversification can reduce company-specific risk, but it cannot prevent market losses.", "Try this: Compare AAPL with SPY or VOO in NOCTIS."),
        ("04 / Reading candlestick charts", "Each candle shows open, high, low and close for one period. The body spans opening and closing prices, while the wicks show the range. A chart describes past trading; patterns do not guarantee future prices.", "Try this: Switch between 1-month and 1-year chart ranges."),
        ("05 / Market orders, limit orders and spreads", "A market order prioritizes execution but does not guarantee the price. A limit order controls the worst price you're willing to accept but may never execute. The bid-ask spread is the gap between quoted buying and selling prices.", "Try this: Practice placing a hypothetical order in the paper-trading ledger."),
        ("06 / Risk, volatility and position sizing", "Volatility measures how much prices fluctuate. Before investing, consider emergency savings, high-interest debt, time horizon, and how much loss you can tolerate. Avoid treating a single prediction or social-media post as certainty.", "Try this: Imagine a position falling 20%; calculate the dollar impact before making a decision."),
        ("07 / How to research a company", "Review revenue, net income, debt, cash flow, and risks. Public US companies publish reports such as Form 10-K (annual) and 10-Q (quarterly) through SEC EDGAR. Valuation measures like price-to-earnings need context.", "Try this: Open SEC EDGAR and search for the company's most recent 10-K."),
        ("08 / Dividends, taxes and fees", "Some companies distribute cash dividends, but they can be reduced or eliminated. Trading costs, fund expense ratios, taxes, and account fees all affect net returns. Tax rules depend on your circumstances and jurisdiction.", "Try this: Compare the expense ratios of two ETFs using their official fund pages."),
        ("09 / Scams, hype and misleading forecasts", "Watch for guaranteed-return claims, pressure to act immediately, fake account screenshots, and unregistered sellers. A backtested model can overfit historical data and fail in live markets.", "Try this: Check an investment professional through Investor.gov before trusting a solicitation."),
        ("10 / Your first practice workflow", "Choose a familiar business or broad-market ETF, read its public disclosures, add it to your watchlist, study the price history, and record a paper trade. Review what happened over time before considering any real investment.", "Try this: Pin a stock, open its profile, and write down one reason it might rise and one reason it might fall."),
    ]
    for title, explanation, exercise in lessons:
        with st.expander(title, expanded=title.startswith('01')):
            st.write(explanation)
            st.markdown(f'<div class="learning-tip"><strong>✦ PRACTICE</strong><p>{exercise}</p></div>', unsafe_allow_html=True)
    st.markdown("### VERIFIED PUBLIC LEARNING RESOURCES")
    st.link_button("Investor.gov — Introduction to Investing ↗", "https://www.investor.gov/introduction-investing")
    st.link_button("FINRA — Investor Education ↗", "https://www.finra.org/investors")
    st.link_button("SEC EDGAR — Company Filings ↗", "https://www.sec.gov/edgar/search/")
    st.link_button("Investor.gov — Check an Investment Professional ↗", "https://www.investor.gov/introduction-investing/investing-basics/investment-professionals")
    st.caption("Educational information only, not personalized financial advice.")



# === NOCTIS v32: shared intelligence, terminal, prediction and data-health layer ===
def v32_signal_frame(history):
    """Deterministic, transparent end-of-day indicator scoring; not an AI forecast."""
    df=indicator_frame(history).copy()
    df["trend20"]=(df["Close"]>df["SMA20"]).astype(int)*2-1
    df.loc[df["SMA20"].isna(),"trend20"]=0
    df["trend50"]=(df["SMA20"]>df["SMA50"]).astype(int)*2-1
    df.loc[df["SMA50"].isna(),"trend50"]=0
    df["momentum"]=(df["MACD_HIST"]>0).astype(int)*2-1
    df["rsi_signal"]=0
    df.loc[df["RSI14"]>=55,"rsi_signal"]=1
    df.loc[df["RSI14"]<=45,"rsi_signal"]=-1
    df["signal_score"]=df[["trend20","trend50","momentum","rsi_signal"]].sum(axis=1)
    df["signal_direction"]=0
    df.loc[df["signal_score"]>=2,"signal_direction"]=1
    df.loc[df["signal_score"]<=-2,"signal_direction"]=-1
    df.loc[df["SMA50"].isna() | df["RSI14"].isna(),"signal_direction"]=0
    return df


def v32_backtest(frame):
    """Hold out last 30% of valid signal observations, assess next-session direction."""
    d=frame.copy()
    d["next_return"]=d["Close"].shift(-1)/d["Close"]-1
    d=d.loc[d["SMA50"].notna() & d["next_return"].notna()]
    if len(d)<65: return None
    holdout=d.iloc[int(len(d)*0.7):]
    active=holdout.loc[holdout["signal_direction"]!=0]
    if len(active)<8: return {"sample":len(active),"insufficient":True}
    correct=((active["next_return"]*active["signal_direction"])>0).mean()
    baseline=(holdout["next_return"]>0).mean()
    return {"sample":len(active),"hit_rate":float(correct),"baseline":float(baseline),"start":str(holdout.index[0].date()),"end":str(holdout.index[-1].date())}


def v32_asset_snapshot(symbol, period="1y"):
    history=trading_history(symbol,period)
    frame=v32_signal_frame(history)
    row=frame.iloc[-1]
    parts=[("Price vs 20-day average",row["trend20"]), ("20-day vs 50-day average",row["trend50"]),
           ("MACD momentum",row["momentum"]),("RSI momentum",row["rsi_signal"])]
    score=int(row["signal_score"])
    label="Bullish" if score>=2 else "Bearish" if score<=-2 else "Mixed / neutral"
    return history,frame,row,parts,score,label,v32_backtest(frame)


def v32_intelligence_workspace():
    st.markdown("### ✦ NOCTIS INTELLIGENCE LAB")
    st.caption("Unified stock/crypto research · explainable indicator scores · held-out historical checks · provider freshness")
    picks=list(dict.fromkeys(load_pins()+["SPY","QQQ","NVDA","AAPL","BTC-USD","ETH-USD","SOL-USD"]))
    a,b,c=st.columns([2,1,1])
    with a:
        selected=st.selectbox("Research asset",picks,key="v32_asset_select")
        custom=st.text_input("Or enter ticker",placeholder="e.g. AMD or SOL-USD",key="v32_asset_custom").strip().upper()
    with b:
        period=st.selectbox("Historical window",["6mo","1y","2y"],index=1,key="v32_period")
    with c:
        st.write("")
        st.write("")
        if st.button("↻ Refresh market data",key="v32_refresh",use_container_width=True):
            trading_history.clear()
            st.rerun()
    symbol=custom or selected
    if not re.fullmatch(r"[A-Z0-9.^=\-]{1,20}",symbol):
        st.error("Invalid ticker format."); return
    try:
        history,frame,row,parts,score,label,test=v32_asset_snapshot(symbol,period)
    except Exception as exc:
        st.warning("Market provider unavailable: "+str(exc)[:170]); return
    latest=history.index[-1]
    asof=str(latest.date())
    stale=(datetime.now(timezone.utc).date()-latest.date()).days
    st.caption(f"Source: Yahoo Finance via yfinance · Last daily candle: {asof} · Displayed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} local · Cache up to 3 minutes · {'Older than 3 calendar days' if stale>3 else 'Recent daily bar'} · NOT real-time")
    if stale>3: st.warning("Data is older than three calendar days. Check the provider and market schedule before interpreting results.")
    m1,m2,m3,m4=st.columns(4)
    m1.metric("LAST DAILY CLOSE",f"${float(row['Close']):,.2f}")
    m2.metric("SIGNAL",label)
    m3.metric("SCORE",f"{score:+d} / 4")
    m4.metric("RSI 14",f"{float(row['RSI14']):.1f}" if pd.notna(row['RSI14']) else "N/A")
    st.caption("Score is a sum of four rule-based indicators, not a calibrated probability or AI confidence rating.")
    saved=load_pins()
    if st.button("★ Saved to watchlist" if symbol in saved else "☆ Save asset to watchlist",key="v33_intel_pin",disabled=symbol in saved):
        save_pins(saved+[symbol]); st.rerun()

    fig=go.Figure()
    fig.add_trace(go.Candlestick(x=frame.index,open=frame['Open'],high=frame['High'],low=frame['Low'],close=frame['Close'],name=symbol))
    fig.add_trace(go.Scatter(x=frame.index,y=frame['SMA20'],name="SMA 20",line=dict(color="#f0cf70",width=1.7)))
    fig.add_trace(go.Scatter(x=frame.index,y=frame['SMA50'],name="SMA 50",line=dict(color="#69d2d3",width=1.7)))
    fig.update_layout(height=420,template="plotly_dark",xaxis_rangeslider_visible=False,paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",margin=dict(l=0,r=0,t=12,b=0))
    st.plotly_chart(fig,use_container_width=True)
    left,right=st.columns(2)
    with left:
        st.markdown("#### Evidence behind the assessment")
        for title,point in parts:
            st.write(("▲" if point>0 else "▼" if point<0 else "•")+" "+title+" — "+("positive" if point>0 else "negative" if point<0 else "neutral"))
        st.caption("Conflicting indicators reduce the score. No external LLM is called and no conclusions are fabricated.")
    with right:
        st.markdown("#### Historical signal evaluation")
        if test and not test.get("insufficient"):
            st.metric("Held-out next-session directional hit rate",f"{test['hit_rate']:.1%}")
            st.caption(f"{test['sample']} non-neutral signals · {test['start']} to {test['end']} · Up-day baseline {test['baseline']:.1%}")
            st.caption("Chronological 70/30 split. This is an exploratory, non-trading backtest; excludes fees, slippage and survivorship effects.")
        else:
            st.info("Not enough historical observations with actionable signals for a meaningful holdout result.")
    st.markdown("#### Compare another asset")
    other=st.selectbox("Comparison",[x for x in picks if x!=symbol] or ["SPY"],key="v32_compare")
    try:
        _,_,other_row,_,other_score,other_label,_=v32_asset_snapshot(other,period)
        comparison=pd.DataFrame([{"Asset":symbol,"Daily close":round(float(row['Close']),4),"Signal":label,"Score":score,"RSI":round(float(row['RSI14']),1)},
                                 {"Asset":other,"Daily close":round(float(other_row['Close']),4),"Signal":other_label,"Score":other_score,"RSI":round(float(other_row['RSI14']),1)}])
        st.dataframe(comparison,hide_index=True,use_container_width=True)
    except Exception as exc:
        st.caption("Comparison data unavailable: "+str(exc)[:110])
    st.caption("Research only. This workspace does not execute trades, provide reliable price targets, or promise predictive accuracy.")

def trading_terminal():
    st.subheader("TRADING TERMINAL")
    st.caption("DISCOVER → INVESTIGATE → PIN · NOCTIS v33")
    view=st.segmented_control("Terminal workspace",["📈 Market Overview","🧠 Intelligence Lab"],default="📈 Market Overview",key="v33_terminal_view",label_visibility="collapsed")
    if view=="🧠 Intelligence Lab":
        v32_intelligence_workspace()
    else:
        market_overview()


def trader_forums_page():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / COMMUNITY</div><div class="terminal-title">TRADER <span>FORUMS</span></div><div class="terminal-sub">Jump to original stock discussions and public trading ideas.</div></div>', unsafe_allow_html=True)
    symbol = st.text_input("FIND DISCUSSIONS BY TICKER", value=st.session_state.get("terminal_research_symbol", "NVDA"), key="forum_ticker").strip().upper()
    if symbol:
        trader_community(symbol, symbol)


@st.cache_data(ttl=120, show_spinner=False)
@st.cache_data(ttl=120, show_spinner=False)
def volume_snapshot(symbols):
    rows = []
    for sym in symbols:
        try:
            hist = yf.Ticker(sym).history(period="5d", interval="1d", auto_adjust=False)
            if hist.empty or "Volume" not in hist:
                continue
            latest = hist.iloc[-1]
            volume = int(latest["Volume"])
            prev = float(hist["Close"].iloc[-2]) if len(hist) > 1 else float(latest["Close"])
            change = (float(latest["Close"]) / prev - 1) * 100 if prev else 0
            rows.append({"Symbol": sym, "Volume (shares/units)": volume, "Last ($)": round(float(latest["Close"]), 2), "Change (%)": round(change, 2), "Session": str(hist.index[-1].date())})
        except Exception:
            pass
    return rows


@st.fragment(run_every="120s")
def live_volume_board(symbols):
    rows = volume_snapshot(tuple(symbols))
    st.caption(f"Last checked: {datetime.now().strftime('%H:%M:%S')} local • Rechecks every 2 minutes • Daily reported volume, not a streaming exchange feed")
    if not rows:
        st.warning("Volume data unavailable. Try again when the data provider responds.")
        return
    df = pd.DataFrame(rows).sort_values("Volume (shares/units)", ascending=False)
    st.dataframe(df, use_container_width=True, hide_index=True)
    fig = go.Figure(go.Bar(x=df["Symbol"], y=df["Volume (shares/units)"], marker_color="#B47AFF"))
    fig.update_layout(height=360, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#EEE"), yaxis=dict(gridcolor="#37313F"), margin=dict(l=10,r=10,t=10,b=10))
    st.plotly_chart(fig, use_container_width=True)


def market_volume_page():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / ACTIVITY MONITOR</div><div class="terminal-title">MARKET <span>VOLUME</span></div><div class="terminal-sub">Automatically refreshing activity board for selected stocks and ETFs.</div></div>', unsafe_allow_html=True)
    st.info("This board refreshes approximately every two minutes while the page is open. Yahoo Finance volume may be delayed, incomplete during the session, or zero outside market hours. It is not tick-by-tick live data.")
    choices = {"Large-cap technology": ["NVDA", "AAPL", "MSFT", "AMD", "TSLA", "META", "AMZN", "GOOGL"], "Major ETFs": ["SPY", "QQQ", "IWM", "DIA", "VOO", "SMH"], "Active retail stocks": ["PLTR", "SOFI", "HOOD", "COIN", "INTC", "RIVN", "F", "NIO"], "My watchlist": load_pins()}
    group = st.selectbox("VOLUME BOARD", list(choices), key="volume_group")
    symbols = choices[group][:12]
    if symbols:
        live_volume_board(symbols)
    else:
        st.info("Pin stocks to My Watchlist to see their volume here.")


def indicator_frame(history):
    """Pure calculations based on historical closes; no look-ahead signals."""
    df = history.copy()
    close = df["Close"].astype(float)
    df["SMA20"] = close.rolling(20, min_periods=20).mean()
    df["SMA50"] = close.rolling(50, min_periods=50).mean()
    delta = close.diff()
    up = delta.clip(lower=0).ewm(alpha=1/14, adjust=False, min_periods=14).mean()
    down = (-delta.clip(upper=0)).ewm(alpha=1/14, adjust=False, min_periods=14).mean()
    rs = up / down.replace(0, float("nan"))
    df["RSI14"] = 100 - 100 / (1 + rs)
    df.loc[(down == 0) & (up > 0), "RSI14"] = 100.0
    df.loc[(down == 0) & (up == 0), "RSI14"] = 50.0
    fast = close.ewm(span=12, adjust=False).mean()
    slow = close.ewm(span=26, adjust=False).mean()
    df["MACD"] = fast - slow
    df["MACD_SIGNAL"] = df["MACD"].ewm(span=9, adjust=False).mean()
    df["MACD_HIST"] = df["MACD"] - df["MACD_SIGNAL"]
    df["VOL_AVG20"] = df["Volume"].rolling(20, min_periods=20).mean()
    return df


@st.cache_data(ttl=180, show_spinner=False)
def trading_history(symbol, period):
    """Refreshable provider history; daily bars are not a streaming price feed."""
    df = yf.Ticker(symbol).history(period=period, interval="1d", auto_adjust=True)
    if df.empty or len(df) < 30:
        raise ValueError("Insufficient historical data returned by Yahoo Finance.")
    return df.dropna(subset=["Open", "High", "Low", "Close"])


def technical_analysis_page(default_crypto=False):
    heading = "CRYPTO <span>INTELLIGENCE</span>" if default_crypto else "TECHNICAL <span>ANALYSIS</span>"
    st.markdown(f'<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / RESEARCH LAB</div><div class="terminal-title">{heading}</div><div class="terminal-sub">Price action, moving averages, momentum and reported trading activity. Research tools — not trade signals.</div></div>', unsafe_allow_html=True)
    crypto = ["BTC-USD", "ETH-USD", "SOL-USD", "XRP-USD", "ADA-USD", "DOGE-USD", "LINK-USD", "AVAX-USD"]
    stocks = ["SPY", "QQQ", "AAPL", "NVDA", "TSLA", "MSFT", "AMD", "COIN"]
    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        selection = st.selectbox("MARKET", crypto if default_crypto else stocks, key=f"indicator_symbol_{default_crypto}")
        custom = st.text_input("OR ENTER A TICKER", placeholder="e.g. BTC-USD or PLTR", key=f"indicator_custom_{default_crypto}").strip().upper()
    with c2:
        period = st.selectbox("HISTORY", ["3mo", "6mo", "1y", "2y"], index=2, key=f"indicator_period_{default_crypto}")
    with c3:
        st.write("")
        st.write("")
        if st.button("↻ Refresh data", key=f"indicator_refresh_{default_crypto}", use_container_width=True):
            trading_history.clear()
            st.rerun()
    symbol = custom or selection
    if not re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", symbol):
        st.error("Invalid ticker format. Try BTC-USD or AAPL.")
        return
    try:
        history = trading_history(symbol, period)
    except Exception as exc:
        st.warning(f"Data unavailable for {symbol}: {str(exc)[:160]}")
        return
    df = indicator_frame(history)
    close = df["Close"].astype(float)
    last, prev = float(close.iloc[-1]), float(close.iloc[-2])
    latest_rsi = df["RSI14"].iloc[-1]
    latest_vol = df["Volume"].iloc[-1]
    avg_vol = df["VOL_AVG20"].iloc[-1]
    cols = st.columns(4)
    cols[0].metric("LAST DAILY CLOSE", f"${last:,.2f}", f"{(last/prev-1)*100:+.2f}%")
    cols[1].metric("RSI · 14", f"{latest_rsi:.1f}" if pd.notna(latest_rsi) else "N/A")
    cols[2].metric("20-DAY AVG", f"${df['SMA20'].iloc[-1]:,.2f}" if pd.notna(df['SMA20'].iloc[-1]) else "N/A")
    cols[3].metric("VOLUME / 20D AVG", f"{latest_vol/avg_vol:.2f}×" if pd.notna(avg_vol) and avg_vol > 0 else "N/A")
    st.caption(f"Yahoo Finance daily history • Last bar: {history.index[-1].strftime('%Y-%m-%d')} • Checked: {datetime.now().strftime('%H:%M:%S')} local • Cached up to 3 minutes • Not live or exchange-verified")
    show_sma = st.checkbox("Overlay 20 / 50-session moving averages", value=True, key=f"indicator_sma_{default_crypto}")
    fig = go.Figure()
    fig.add_trace(go.Candlestick(x=df.index, open=df["Open"], high=df["High"], low=df["Low"], close=df["Close"], name=symbol, increasing_line_color="#C493FF", decreasing_line_color="#F07091"))
    if show_sma:
        fig.add_trace(go.Scatter(x=df.index, y=df["SMA20"], mode="lines", name="SMA 20", line=dict(color="#FFE17B", width=1.7)))
        fig.add_trace(go.Scatter(x=df.index, y=df["SMA50"], mode="lines", name="SMA 50", line=dict(color="#62D9DB", width=1.7)))
    fig.update_layout(height=460, xaxis_rangeslider_visible=False, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=5,r=5,t=15,b=10), legend=dict(orientation="h"))
    st.plotly_chart(fig, use_container_width=True)
    left, right = st.columns(2)
    with left:
        st.markdown("#### RSI / MOMENTUM")
        rsi_fig = go.Figure(go.Scatter(x=df.index, y=df["RSI14"], mode="lines", line=dict(color="#C493FF"), name="RSI 14"))
        rsi_fig.add_hline(y=70, line_dash="dash", line_color="#F07091")
        rsi_fig.add_hline(y=30, line_dash="dash", line_color="#62D9DB")
        rsi_fig.update_layout(height=290, yaxis_range=[0,100], template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=5,r=5,t=10,b=10))
        st.plotly_chart(rsi_fig, use_container_width=True)
    with right:
        st.markdown("#### MACD / TREND MOMENTUM")
        macd_fig = go.Figure()
        macd_fig.add_trace(go.Bar(x=df.index, y=df["MACD_HIST"], name="Histogram", marker_color="#8E64C9"))
        macd_fig.add_trace(go.Scatter(x=df.index, y=df["MACD"], name="MACD", line=dict(color="#FFE17B")))
        macd_fig.add_trace(go.Scatter(x=df.index, y=df["MACD_SIGNAL"], name="Signal", line=dict(color="#62D9DB")))
        macd_fig.update_layout(height=290, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=5,r=5,t=10,b=10), legend=dict(orientation="h"))
        st.plotly_chart(macd_fig, use_container_width=True)
    st.markdown("#### REPORTED DAILY VOLUME")
    vol_fig = go.Figure(go.Bar(x=df.index, y=df["Volume"], marker_color="#B47AFF", name="Volume"))
    vol_fig.add_trace(go.Scatter(x=df.index, y=df["VOL_AVG20"], name="20-session average", line=dict(color="#FFE17B")))
    vol_fig.update_layout(height=250, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=5,r=5,t=10,b=10))
    st.plotly_chart(vol_fig, use_container_width=True)
    with st.expander("Understanding the indicators", expanded=False):
        st.write("**SMA 20 / 50:** average closing prices across 20 and 50 sessions. **RSI 14:** a momentum indicator; above 70 or below 30 does not guarantee a reversal. **MACD:** difference between two exponential averages, with a signal line. **Volume ratio:** last reported daily volume divided by the 20-session average. None predicts future returns reliably on its own.")
    if default_crypto:
        st.info("Crypto trades around the clock. Daily candle boundaries depend on the provider's timezone; 24-hour changes may not match daily close-to-close changes. Volume units vary by asset and provider.")
    st.caption("Educational research only. Data can be delayed, revised, or missing. No trades are executed.")


@st.cache_data(ttl=900, show_spinner=False)
def pokemon_card_lookup(query):
    # Optional public Pokémon TCG API, subject to provider rate limits.
    endpoint = "https://api.pokemontcg.io/v2/cards?" + urlencode({"q": 'name:"' + query.replace('"', '') + '"', "pageSize": 24, "select": "id,name,set,number,tcgplayer,cardmarket,images,rarity"})
    req = Request(endpoint, headers={"User-Agent": "NOCTIS-LocalResearch/1.0"})
    with urlopen(req, timeout=9) as response:
        return json.loads(response.read(750000)).get("data", [])


FEATURED_CARDS = [
    {"name":"Charizard", "set":"Base Set", "number":"4/102", "id":"base1-4", "rarity":"Holo Rare"},
    {"name":"Blastoise", "set":"Base Set", "number":"2/102", "id":"base1-2", "rarity":"Holo Rare"},
    {"name":"Venusaur", "set":"Base Set", "number":"15/102", "id":"base1-15", "rarity":"Holo Rare"},
    {"name":"Umbreon VMAX", "set":"Evolving Skies", "number":"215/203", "id":"swsh7-215", "rarity":"Secret Rare"},
    {"name":"Pikachu", "set":"Base Set", "number":"58/102", "id":"base1-58", "rarity":"Common"},
    {"name":"Mewtwo", "set":"Base Set", "number":"10/102", "id":"base1-10", "rarity":"Holo Rare"},
]


def pokemon_market_page():
    st.markdown("""<div class='alt-hero'><div class='alt-eyebrow'>✦ NOCTIS / COLLECTIBLES INTELLIGENCE</div>
    <div class='alt-title'>POKÉMON <span>MARKET EXPLORER</span></div>
    <div class='alt-sub'>Browse iconic cards, see their artwork, research recent sales and compare published price references when available.</div></div>""", unsafe_allow_html=True)

    st.markdown("""<style>
    .pokemon-ribbon {padding:15px 20px;border:1px solid #f5cf54;border-radius:16px;background:linear-gradient(110deg,#25202d,#182e32);margin:8px 0 18px;}
    .pokemon-ribbon b {color:#ffe17a;letter-spacing:1px;}
    .pokemon-ribbon span {color:#d3cce0;}
    </style>""", unsafe_allow_html=True)
    st.markdown('<div class="pokemon-ribbon"><b>⚡ CARD SHOWCASE</b><br><span>Artwork gallery · individual card research · live API lookup when available</span></div>', unsafe_allow_html=True)

    st.subheader("Featured card gallery")
    st.caption("The featured gallery is always available. Artwork is loaded from the Pokémon TCG image CDN; an internet connection is needed.")
    featured_cols = st.columns(3)
    for i, card in enumerate(FEATURED_CARDS):
        with featured_cols[i % 3]:
            with st.container(border=True):
                # Stable card IDs provide a useful gallery even if the card-search API is rate-limited.
                st.image(f"https://images.pokemontcg.io/{card['id'].replace('-', '/')}.png", use_container_width=True)
                st.markdown(f"**{card['name']}**")
                st.caption(f"{card['set']} · #{card['number']} · {card['rarity']}")
                if st.button("Inspect card ✦", key=f"featured_{card['id']}", use_container_width=True):
                    st.session_state["pokemon_selected_card"] = card
                    st.rerun()

    selected = st.session_state.get("pokemon_selected_card")
    if selected:
        st.divider()
        st.subheader(f"✦ Card dossier / {selected['name']}")
        a, b = st.columns([1, 2])
        with a:
            st.image(f"https://images.pokemontcg.io/{selected['id'].replace('-', '/')}.png", use_container_width=True)
        with b:
            st.markdown(f"### {selected['name']}")
            st.write(f"**Set:** {selected['set']}")
            st.write(f"**Card number:** {selected['number']}")
            st.write(f"**Rarity:** {selected['rarity']}")
            st.info("Card condition and grading change its value dramatically. No live price is claimed without a provider quote.")
            query = quote_plus(f"{selected['name']} {selected['set']} {selected['number']} pokemon card")
            st.link_button("View completed eBay sales ↗", f"https://www.ebay.com/sch/i.html?_nkw={query}&LH_Sold=1&LH_Complete=1", use_container_width=True)
            st.link_button("Compare PriceCharting ↗", f"https://www.pricecharting.com/search-products?type=prices&q={query}", use_container_width=True)
            st.link_button("Search TCGplayer ↗", f"https://www.tcgplayer.com/search/pokemon/product?productLineName=pokemon&q={query}", use_container_width=True)
            if st.button("Close card dossier"):
                st.session_state.pop("pokemon_selected_card", None)
                st.rerun()

    st.divider()
    st.subheader("Search the card database")
    query = st.text_input("Card name", value="Charizard", placeholder="Charizard, Pikachu, Umbreon...", key="pokemon_card_search").strip()
    c1, c2 = st.columns([1, 3])
    with c1:
        search_clicked = st.button("Search cards", use_container_width=True, key="pokemon_lookup")
    with c2:
        st.caption("Search is on demand. This avoids repeated API requests every time you click a gallery card.")
    if search_clicked:
        st.session_state["pokemon_last_query"] = query
    lookup = st.session_state.get("pokemon_last_query", "")
    if lookup:
        try:
            with st.spinner("Loading card records and artwork..."):
                cards = pokemon_card_lookup(lookup)
        except Exception as exc:
            cards = []
            st.warning("The live card database is unavailable or rate-limited. The featured gallery above remains usable.")
            with st.expander("Connection details"):
                st.code(str(exc)[:300])
        if cards:
            st.success(f"Loaded {len(cards)} card records for {lookup}.")
            for i in range(0, len(cards), 3):
                cols = st.columns(3)
                for col, card in zip(cols, cards[i:i+3]):
                    with col:
                        with st.container(border=True):
                            images = card.get("images") or {}
                            url = images.get("large") or images.get("small")
                            if url and url.startswith("https://"):
                                st.image(url, use_container_width=True)
                            st.markdown(f"**{card.get('name','Unknown')}**")
                            setname = (card.get("set") or {}).get("name", "Unknown set")
                            st.caption(f"{setname} · #{card.get('number','?')} · {card.get('rarity','Rarity not listed')}")
                            groups = (card.get("tcgplayer") or {}).get("prices") or {}
                            quotes = [(label, value.get("market")) for label, value in groups.items() if isinstance(value,dict) and isinstance(value.get("market"),(int,float))]
                            if quotes:
                                for label, value in quotes[:3]:
                                    st.write(f"{label}: **${value:,.2f}**")
                            else:
                                st.caption("No published price reference")
                            q = quote_plus(f"{card.get('name','')} {setname} {card.get('number','')} pokemon card")
                            st.link_button("Check sold listings ↗", f"https://www.ebay.com/sch/i.html?_nkw={q}&LH_Sold=1&LH_Complete=1", use_container_width=True)
            rows = []
            for card in cards:
                groups = (card.get("tcgplayer") or {}).get("prices") or {}
                values = [v.get("market") for v in groups.values() if isinstance(v,dict) and isinstance(v.get("market"),(int,float))]
                if values:
                    rows.append({"Card":f"{card.get('name','')} / {(card.get('set') or {}).get('name','')}","Reference price ($)":max(values)})
            if rows:
                st.subheader("Published price comparison")
                st.caption("One-time reference prices for different card versions, not a historical stock chart.")
                df = pd.DataFrame(rows).sort_values("Reference price ($)", ascending=False).head(12)
                fig = go.Figure(go.Bar(x=df["Reference price ($)"],y=df["Card"],orientation="h",marker_color="#D0A2FF"))
                fig.update_layout(height=max(340,len(df)*42),paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font=dict(color="#F0E8F8"),yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig,use_container_width=True)
        elif search_clicked:
            st.info("No cards returned. Try another name or use the featured gallery.")

    with st.expander("How to evaluate a Pokémon card before buying or selling"):
        st.markdown("**1.** Match name, set, collector number, language, finish and edition.\n\n**2.** Check raw condition versus PSA/CGC/BGS grade.\n\n**3.** Compare completed sales, not only active asking prices.\n\n**4.** Check the date, currency and quantity of comparable sales.\n\n**5.** Be careful with extremely rare cards: one unusual sale is not a reliable market price.")


def sportsbook_research_page():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / ODDS INTELLIGENCE</div><div class="terminal-title">SPORTS & <span>PREDICTION MARKETS</span></div><div class="terminal-sub">Compare public research destinations and inspect event probabilities without placing bets.</div></div>', unsafe_allow_html=True)
    st.warning("Information only. Market-implied probabilities reflect prices and fees, not guaranteed outcomes. Access, legality, and age requirements vary by jurisdiction.")
    st.markdown("### Prediction market research")
    c1, c2 = st.columns(2)
    with c1:
        with st.container(border=True):
            st.markdown("#### Polymarket")
            st.write("Browse event markets, prices and publicly displayed trading activity.")
            st.link_button("Open Polymarket ↗", "https://polymarket.com/", use_container_width=True)
    with c2:
        with st.container(border=True):
            st.markdown("#### Kalshi")
            st.write("Explore event contracts and public market information.")
            st.link_button("Open Kalshi ↗", "https://kalshi.com/markets", use_container_width=True)
    st.markdown("### Sports odds research")
    c1, c2 = st.columns(2)
    with c1:
        st.link_button("ESPN scores & schedules ↗", "https://www.espn.com/", use_container_width=True)
        st.link_button("DraftKings sportsbook ↗", "https://sportsbook.draftkings.com/", use_container_width=True)
    with c2:
        st.link_button("FanDuel sportsbook ↗", "https://sportsbook.fanduel.com/", use_container_width=True)
        st.link_button("Sports Reference ↗", "https://www.sports-reference.com/", use_container_width=True)
    st.caption("External websites may require accounts or may be unavailable in your area. No live sportsbook API, account linking, or bet placement is included.")
    st.divider()
    st.markdown("### Probability explorer")
    odds = st.number_input("Decimal odds (example only)", min_value=1.01, max_value=1000.0, value=2.00, step=0.05, key="sports_odds")
    st.metric("Raw implied probability", f"{100 / odds:.2f}%")
    st.caption("1 / decimal odds, before bookmaker margin or fees. Not a calibrated forecast.")
    with st.expander("Compare implied probabilities across example odds"):
        example_odds = [1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0]
        fig = go.Figure(go.Bar(x=[str(x) for x in example_odds], y=[100 / x for x in example_odds], marker_color="#24D6C8"))
        fig.update_layout(title="Illustrative decimal odds vs implied probability", xaxis_title="Decimal odds", yaxis_title="Implied probability (%)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#E4F5F3"), height=350)
        st.plotly_chart(fig, use_container_width=True)
        st.caption("These are mathematical examples, not live prices from sportsbooks.")
    with st.expander("Sports research checklist and public data sources"):
        st.markdown("Check injuries, lineup confirmations, travel/rest, recent performance, sample size, market timestamp, fees and bookmaker margin. Compare the underlying event definition before comparing probabilities.")
        st.link_button("ESPN schedules and scores ↗", "https://www.espn.com/")
        st.link_button("Sports Reference statistics ↗", "https://www.sports-reference.com/")



def trading_asset_workspace():
    st.subheader("STOCK SEARCH / RESEARCH")
    st.caption("HISTORICAL MARKET DATA • PAPER TRADING ONLY")

    symbols = {"Apple": "AAPL", "Microsoft": "MSFT", "NVIDIA": "NVDA", "S&P 500 ETF": "SPY", "Bitcoin (USD)": "BTC-USD", "Tesla": "TSLA"}
    left, mid, right = st.columns([2, 2, 1])
    with left:
        preset = st.selectbox("POPULAR SYMBOLS", list(symbols), key="trading_ticker")
    with mid:
        custom = st.text_input("SEARCH ANY TICKER", placeholder="Search Apple, AMD, Palantir, Bitcoin or a ticker...", key="custom_ticker").strip().upper()
    if custom and not re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", custom):
        st.warning("Search with a ticker or a company name.")
        return
    if custom:
        matches = search_assets(custom)
        if matches:
            options = {f"{label}  ·  {symbol}": symbol for symbol, label in matches}
            picked = st.selectbox("MATCHING COMPANIES / SELECT TO ANALYZE", list(options), key="terminal_search_result")
            ticker = options[picked]
        else:
            ticker = custom
    else:
        ticker = symbols[preset]
    name = ticker
    if not re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", ticker):
        st.warning("Enter a valid ticker symbol, for example AAPL or BTC-USD.")
        return
    with right:
        st.write("")
        st.write("")
        if st.button("Refresh prices"):
            fetch_market_history.clear()
            st.rerun()
    pinned = load_pins()
    if ticker in pinned:
        if st.button(f"★ Unpin {ticker}"):
            save_pins([x for x in pinned if x != ticker])
            st.rerun()
    else:
        if st.button(f"☆ Pin {ticker} to watchlist"):
            save_pins(pinned + [ticker])
            st.rerun()

    try:
        with st.spinner("Loading market history..."):
            history = fetch_market_history(ticker)
    except Exception as exc:
        st.error("Market data could not be loaded. Check your internet connection or try again later.")
        st.caption(f"Provider detail: {str(exc)[:180]}")
        return

    last = float(history["Close"].iloc[-1])
    previous = float(history["Close"].iloc[-2])
    change = (last / previous - 1) * 100
    asof = history.index[-1]
    st.caption(f"Source: Yahoo Finance via yfinance • Last available daily candle: {asof.strftime('%Y-%m-%d')} • Adjusted historical OHLC • May be delayed")

    a, b, c, d = st.columns(4)
    a.metric("LATEST DAILY CLOSE", f"${last:,.2f}", f"{change:+.2f}% vs prior close")
    b.metric("30-SESSION HIGH", f"${history['High'].tail(30).max():,.2f}")
    c.metric("30-SESSION LOW", f"${history['Low'].tail(30).min():,.2f}")
    d.metric("HISTORY", f"{len(history):,} daily candles")

    chart_tab, trades_tab, forecast_tab = st.tabs(["CANDLESTICKS", "PAPER TRADES & HISTORY", "AI FORECAST LAB"])
    with chart_tab:
        window = st.select_slider("Chart range", options=["1M", "3M", "6M", "1Y", "2Y"], value="6M")
        days = {"1M": 22, "3M": 65, "6M": 130, "1Y": 252, "2Y": 504}[window]
        shown = history.tail(days)
        fig = go.Figure(go.Candlestick(
            x=shown.index, open=shown["Open"], high=shown["High"],
            low=shown["Low"], close=shown["Close"],
            increasing_line_color="#f5f5f5", decreasing_line_color="#888888",
            increasing_fillcolor="#ededed", decreasing_fillcolor="#555555",
            name=ticker,
        ))
        fig.update_layout(
            height=480, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#eeeeee"), xaxis_rangeslider_visible=False,
            xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#333333", title="USD"),
            margin=dict(l=10, r=10, t=25, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Daily candles, not streaming intraday quotes. Bitcoin trades every day; stocks trade on market sessions.")

    with trades_tab:
        st.subheader("Paper trading ledger")
        st.caption("Demo orders use the latest available daily close, not an executable market quote. Trades are not sent to a broker.")
        if "noctis_ledger" not in st.session_state:
            st.session_state.noctis_ledger = []
        with st.form("paper_order", clear_on_submit=False):
            c1, c2, c3 = st.columns(3)
            with c1:
                side = st.selectbox("Action", ["BUY", "SELL"])
            with c2:
                order_symbol = st.selectbox("Asset", list(dict.fromkeys([ticker] + list(symbols.values()) + load_pins())))
            with c3:
                quantity = st.number_input("Quantity", min_value=0.01, value=1.0, step=1.0)
            submit = st.form_submit_button("Record paper trade")
        if submit:
            symbol = order_symbol
            try:
                price = float(fetch_market_history(symbol)["Close"].iloc[-1])
                owned = sum((t["Quantity"] if t["Action"] == "BUY" else -t["Quantity"]) for t in st.session_state.noctis_ledger if t["Symbol"] == symbol)
                if side == "SELL" and quantity > owned + 1e-8:
                    st.error(f"Cannot sell {quantity:g}: only {owned:g} paper units held.")
                else:
                    st.session_state.noctis_ledger.append({
                        "Recorded at (UTC)": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                        "Action": side, "Symbol": symbol, "Quantity": float(quantity),
                        "Demo fill ($)": round(price, 4),
                    })
                    st.success(f"Recorded {side} {quantity:g} {symbol} at demo price ${price:,.2f}")
            except Exception:
                st.error("Could not load the asset price. No trade recorded.")

        ledger = st.session_state.noctis_ledger
        if ledger:
            frame = pd.DataFrame(ledger)
            st.dataframe(frame, use_container_width=True, hide_index=True)
            st.download_button("Download trade history (CSV)", frame.to_csv(index=False), file_name="noctis_paper_trades.csv", mime="text/csv")
            st.subheader("Open paper positions")
            positions = []
            for sym in sorted(set(frame["Symbol"])):
                trades = [t for t in ledger if t["Symbol"] == sym]
                held = sum(t["Quantity"] if t["Action"] == "BUY" else -t["Quantity"] for t in trades)
                if held > 1e-8:
                    # Weighted-average cost accounting; sales reduce quantity at average cost.
                    units, basis = 0.0, 0.0
                    for t in trades:
                        if t["Action"] == "BUY":
                            basis += t["Quantity"] * t["Demo fill ($)"]
                            units += t["Quantity"]
                        elif units > 0:
                            basis -= (basis / units) * t["Quantity"]
                            units -= t["Quantity"]
                    try:
                        market = float(fetch_market_history(sym)["Close"].iloc[-1])
                        positions.append({"Symbol": sym, "Quantity": round(held, 4), "Market value ($)": round(held * market, 2), "Unrealized P/L ($)": round(held * market - basis, 2)})
                    except Exception:
                        st.warning(f"Could not value {sym} right now.")
            if positions:
                st.dataframe(pd.DataFrame(positions), use_container_width=True, hide_index=True)
            if st.button("Clear paper trade history"):
                st.session_state.noctis_ledger = []
                st.rerun()
        else:
            st.info("No paper trades yet. Record a BUY to start your history.")
        st.caption("Paper trade history lives in this browser session. Download CSV to keep a copy; it is not a permanent account or brokerage record.")

    with forecast_tab:
        st.subheader(f"Experimental AI forecast / {ticker}")
        st.write("A small random-forest model uses past daily returns, short-term momentum, and volatility to estimate the next trading day's percentage change.")
        with st.spinner("Training and checking historical forecasts..."):
            result = evaluate_forecast(history)
        if result is None:
            st.warning("Not enough history for this model.")
        else:
            mae, accuracy, next_prediction, comparison = result
            m1, m2, m3 = st.columns(3)
            m1.metric("NEXT-SESSION MODEL ESTIMATE", f"{next_prediction:+.2f}%")
            m2.metric("HOLDOUT DIRECTION ACCURACY", f"{accuracy:.1f}%")
            m3.metric("HOLDOUT MEAN ERROR", f"{mae:.2f} pp")
            st.line_chart(comparison.tail(45))
            st.caption("Historical test: first 80% of labeled days used for training, final 20% held out. The chart compares model predictions with actual next-session changes. No future outcome is known for the newest estimate.")
            st.warning("Research demonstration only. This model is not validated for live trading, does not account for trading costs, and may perform worse than chance. Not financial advice.")


def gambling_research():
    st.subheader("GAMBLING SITE RESEARCH")
    st.caption("Public information and tools • No betting integration, accounts, or wagering")
    st.info("This section is a research workspace, not a live odds feed. Gambling laws and site availability vary by location. Check licensing and eligibility before using a service.")

    st.markdown("#### Open a website you want to research")
    website = st.text_input("Website address", placeholder="https://example.com", key="research_site_url")
    if website:
        from urllib.parse import urlparse
        parsed = urlparse(website.strip())
        if parsed.scheme in ("https", "http") and parsed.netloc and not any(c.isspace() for c in website):
            st.link_button("Open website ↗", website.strip())
        else:
            st.warning("Enter a complete http:// or https:// website address.")

    st.markdown("#### Decimal odds calculator")
    c1, c2 = st.columns(2)
    with c1:
        decimal_odds = st.number_input("Decimal odds", min_value=1.01, value=2.00, step=0.05)
    with c2:
        stake = st.number_input("Example stake ($)", min_value=0.0, value=10.0, step=5.0)
    a, b, c = st.columns(3)
    a.metric("Implied probability", f"{100 / decimal_odds:.1f}%")
    b.metric("Potential total return", f"${stake * decimal_odds:,.2f}")
    c.metric("Potential net profit", f"${stake * (decimal_odds - 1):,.2f}")
    st.caption("Hypothetical calculations only. These figures exclude fees, taxes, and any other outcomes. Odds imply a probability, not a prediction of what will happen.")

    st.markdown("#### Public information")
    st.link_button("American Gaming Association — state gaming regulations ↗", "https://www.americangaming.org/state-of-play/")
    st.link_button("National Council on Problem Gambling ↗", "https://www.ncpgambling.org/")
    st.caption("NOCTIS does not recommend gambling sites or place bets.")


@st.cache_data(ttl=1800, show_spinner=False)
def youtube_recent_uploads(channel_id):
    """YouTube's public channel Atom feed; no API key required, if accessible."""
    url = f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"
    request = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; NOCTIS/1.0)"})
    with urlopen(request, timeout=9) as response:
        data = response.read(250000)
    root = ET.fromstring(data)
    atom = "{http://www.w3.org/2005/Atom}"
    yt = "{http://www.youtube.com/xml/schemas/2015}"
    items = []
    for entry in root.findall(f"{atom}entry"):
        title = entry.findtext(f"{atom}title", default="Video")
        video_id = entry.findtext(f"{yt}videoId", default="")
        published = entry.findtext(f"{atom}published", default="")
        if re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id):
            items.append({"title": title, "video_id": video_id, "published": published[:16].replace("T", " ") + " UTC"})
    return items


def market_videos():
    st.subheader("MARKET VIDEOS & LIVE")
    st.caption("Public YouTube videos and links to live trading coverage. Live status is determined by YouTube, not NOCTIS.")

    search_term = st.text_input("SEARCH YOUTUBE FOR MARKET COVERAGE", value="stock market live", key="video_search_term").strip()
    query = quote_plus(search_term or "stock market live")
    a, b = st.columns(2)
    with a:
        st.link_button("Find live market streams ↗", f"https://www.youtube.com/results?search_query={query}&sp=EgJAAQ%253D%253D", use_container_width=True)
    with b:
        st.link_button("Find recent market videos ↗", f"https://www.youtube.com/results?search_query={query}&sp=CAI%253D", use_container_width=True)
    st.caption("Search results open on YouTube; stream availability and upload times can change.")

    st.divider()
    st.markdown("#### Recent uploads from market news channels")
    sources = {
        "CNBC Television": "UCvJJ_dzjViJCoLf5uKUTwoA",
        "Bloomberg Television": "UChirEOpgFCupRAk5etXqPaA",
    }
    source = st.selectbox("Channel", list(sources), key="video_channel")
    try:
        items = youtube_recent_uploads(sources[source])
    except Exception:
        items = []
    if items:
        for item in items[:6]:
            with st.container(border=True):
                st.markdown(f"**{item['title']}**")
                st.caption(f"Published: {item['published']} • {source}")
                st.link_button("Watch on YouTube ↗", f"https://www.youtube.com/watch?v={item['video_id']}")
                if st.button("Play here", key=f"play_{item['video_id']}"):
                    st.session_state["noctis_video_id"] = item["video_id"]
                    st.session_state["noctis_video_url"] = ""
                if st.session_state.get("noctis_video_id") == item["video_id"] and not st.session_state.get("noctis_video_url"):
                    st.video(f"https://www.youtube.com/watch?v={item['video_id']}")
                    st.caption("Video player appears directly under the selected upload. Embedding is controlled by YouTube and the video owner.")
    else:
        st.info("Recent uploads could not be retrieved from this channel right now. Use the YouTube search links above or paste a video URL below.")

    st.divider()
    st.markdown("#### Video player")
    url = st.text_input("Paste a YouTube video or livestream URL", placeholder="https://www.youtube.com/watch?v=...", key="video_url")
    chosen = st.session_state.get("noctis_video_id")
    if url:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
        candidate = ""
        if host in ("youtube.com", "www.youtube.com", "m.youtube.com"):
            if parsed.path == "/watch":
                candidate = parse_qs(parsed.query).get("v", [""])[0]
            elif parsed.path.startswith(("/live/", "/shorts/", "/embed/")):
                candidate = parsed.path.split("/")[2]
        elif host == "youtu.be":
            candidate = parsed.path.strip("/").split("/")[0]
        if re.fullmatch(r"[A-Za-z0-9_-]{11}", candidate):
            chosen = candidate
        else:
            st.warning("Please enter a valid YouTube video or livestream URL.")
            chosen = None
    if chosen and url:
        st.video(f"https://www.youtube.com/watch?v={chosen}")
        st.caption("Playback depends on whether the video owner permits embedding. Some livestreams may only play on YouTube.")


st.markdown("""
<style>
.noctis-home-hero{padding:30px 32px;border-radius:20px;border:1px solid #68448B;background:linear-gradient(110deg,#251633,#14141C 70%,#121F24);margin-bottom:25px;}
.home-kicker{color:#D4B0FF;font-size:11px;font-weight:800;letter-spacing:2px;}
.home-heading{font-size:clamp(32px,5vw,56px);font-weight:800;letter-spacing:-2px;color:#F9F5FF;line-height:1.25;margin:8px 0;}
.home-heading span{color:#C592FF;}
.home-sub{color:#C5BCCF;font-size:14px;}

@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root {--noctis-purple:#B47AFF;--noctis-purple-bright:#D9B8FF;--noctis-bg:#090A0E;--noctis-card:#15161D;--noctis-line:#34303E;--noctis-muted:#A8A7B4;--noctis-yellow:#FFD76B;}
html,body,[class*="css"],.stApp {font-family:'DM Sans',sans-serif;}
.stApp {background:radial-gradient(ellipse 55% 28% at 88% 0%,#251532 0%,transparent 80%),radial-gradient(ellipse 40% 35% at 0% 100%,#171123 0%,transparent 90%),var(--noctis-bg);color:#F3F1F8;}
.block-container {max-width:1500px;padding-top:2rem;padding-bottom:5rem;}
h1,h2,h3,h4 {font-family:'Space Grotesk',sans-serif!important;color:#F9F7FF!important;letter-spacing:-.035em;line-height:1.18;}
h1 {font-size:2.15rem!important;font-weight:700!important;}
h2 {font-size:1.5rem!important;font-weight:650!important;}
h3 {font-size:1.18rem!important;font-weight:650!important;}
p,li {line-height:1.65;}
[data-testid="stCaptionContainer"],small {color:var(--noctis-muted)!important;letter-spacing:.012em;}
hr {border-color:#292630!important;margin:1.25rem 0!important;}
/* Sidebar: crisp, spacious, clear active navigation */
[data-testid="stSidebar"] {background:linear-gradient(180deg,#15111D 0%,#0D0E13 65%,#0B0C10 100%);border-right:1px solid #3A294D;}
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {padding-top:2.2rem;}
[data-testid="stSidebar"] h1 {font-size:2rem!important;letter-spacing:.025em;color:#F4E9FF!important;text-shadow:0 0 22px #9B50F34D;}
[data-testid="stSidebar"] [role="radiogroup"] {gap:.55rem;}
[data-testid="stSidebar"] [role="radiogroup"] label {border:1px solid transparent;border-radius:12px;padding:.75rem .9rem;transition:background .15s,border-color .15s;background:#FFFFFF05;}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {background:#B47AFF15;border-color:#B47AFF50;}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {background:linear-gradient(90deg,#6B39A64D,#6B39A611);border-color:#A06CE1;box-shadow:inset 3px 0 0 #C28AFF;}
[data-testid="stSidebar"] [role="radiogroup"] label p {font-weight:600;letter-spacing:.005em;}
/* Consistent dashboard surfaces */
[data-testid="stMetric"] {background:linear-gradient(140deg,#1D1A25,#111217);border:1px solid #3B3249;border-radius:15px;padding:20px 22px;box-shadow:0 8px 26px #00000020;}
[data-testid="stMetricLabel"] {color:#BDB5C9!important;font-size:.75rem!important;font-weight:700!important;letter-spacing:.075em;text-transform:uppercase;}
[data-testid="stMetricValue"] {color:#FAF8FF!important;font-family:'Space Grotesk',sans-serif;font-weight:700;letter-spacing:-.04em;}
[data-testid="stMetricDelta"] {font-weight:700;}
[data-testid="stVerticalBlockBorderWrapper"] {border-color:#383340!important;border-radius:16px!important;}
[data-testid="stVerticalBlockBorderWrapper"]:has(> div) {background-color:#FFFFFF02;}
[data-testid="stDataFrame"] {border:1px solid #463650;border-radius:13px;overflow:hidden;box-shadow:0 10px 35px #00000022;}
/* Tabs are navigation, not bare text */
.stTabs [data-baseweb="tab-list"] {gap:.4rem;border-bottom:1px solid #3A3046;padding-bottom:.4rem;flex-wrap:wrap;}
.stTabs [data-baseweb="tab"] {font-weight:700;letter-spacing:.035em;font-size:.78rem;padding:.7rem 1.1rem;border-radius:10px 10px 0 0;color:#BDB6C8;}
.stTabs [aria-selected="true"] {background:#B47AFF18!important;color:#E1C3FF!important;}
.stTabs [data-baseweb="tab-highlight"] {background-color:#B47AFF!important;height:3px;}
/* Inputs and actions */
.stButton button,.stLinkButton a,.stDownloadButton button,.stFormSubmitButton button {border-radius:10px!important;border:1px solid #69517E!important;background:linear-gradient(145deg,#292035,#1A1822)!important;color:#F7F1FF!important;font-weight:700!important;transition:border-color .15s,box-shadow .15s,transform .15s;}
.stButton button:hover,.stLinkButton a:hover,.stDownloadButton button:hover,.stFormSubmitButton button:hover {border-color:#C18CFF!important;box-shadow:0 0 0 2px #B47AFF22,0 6px 24px #9B50F329!important;transform:translateY(-1px);}
.stButton button:disabled {opacity:.5;transform:none;}
[data-baseweb="input"],[data-baseweb="select"]>div,[data-baseweb="base-input"] {border-radius:10px!important;background:#15151D!important;border-color:#494050!important;}
[data-baseweb="input"]:focus-within,[data-baseweb="base-input"]:focus-within {outline:1px solid #BA86FA!important;}
[data-testid="stWidgetLabel"] p {color:#D7CFE0!important;font-weight:700!important;font-size:.83rem!important;letter-spacing:.015em;}
[data-testid="stExpander"] {border:1px solid #443D4D!important;border-radius:12px!important;background:#15131B!important;overflow:hidden;}
[data-testid="stExpander"] summary {font-weight:700;color:#F1EAFB;}
[data-testid="stAlert"] {border-radius:12px!important;}
/* Purposeful purple hero headers */
.terminal-hero,.noctis-watch-hero {position:relative;overflow:hidden;padding:36px 36px;border:1px solid #8350B3;border-radius:20px;background:radial-gradient(ellipse at 85% 10%,#482265 0%,transparent 56%),linear-gradient(125deg,#1A1423,#111116 78%);box-shadow:0 14px 42px #00000040,0 0 28px #A45CFF12;margin:12px 0 25px;}
.terminal-hero:after,.noctis-watch-hero:after {content:'';position:absolute;right:-50px;top:-75px;width:230px;height:230px;border:1px solid #B47AFF28;border-radius:50%;box-shadow:0 0 0 32px #B47AFF0A,0 0 0 70px #B47AFF07;pointer-events:none;}
.terminal-kicker,.watch-eyebrow {color:#D9B8FF;font-size:11px;font-weight:800;letter-spacing:3px;text-transform:uppercase;}
.terminal-title,.watch-title {font-family:'Space Grotesk',sans-serif;font-size:clamp(33px,4.6vw,56px);font-weight:700;letter-spacing:-2px;line-height:1.1;color:#FFF;margin:14px 0;}
.terminal-title span,.watch-title span {color:#C493FF;text-shadow:0 0 28px #AA63FF60;}
.terminal-sub,.watch-sub {color:#C5BBD0;font-size:15px;max-width:680px;line-height:1.6;}
/* Educational yellow is reserved for important concepts */
.beginner-hero {padding:36px;border-radius:20px;border:1px solid #9C7B32;background:radial-gradient(ellipse at 90% 0%,#4D3A19,transparent 58%),linear-gradient(115deg,#241F16,#121316 80%);margin:12px 0 25px;box-shadow:0 10px 36px #00000030;}
.beginner-kicker {color:#FFE58A;font-size:11px;font-weight:800;letter-spacing:3px;}
.beginner-title {font-family:'Space Grotesk',sans-serif;font-size:clamp(30px,4vw,49px);font-weight:700;letter-spacing:-1.7px;color:#FFF5C8;margin:12px 0;}
.beginner-sub {color:#E0D5B4;line-height:1.6;}
.learning-tip {border-left:4px solid #FFD76B;background:#302917;border-radius:8px;padding:15px 18px;margin:14px 0;color:#F7EAC5;}
.learning-tip strong {color:#FFE68A;font-size:.8rem;letter-spacing:1.5px;}
.learning-tip p {margin:6px 0 0;}
@media(max-width:700px){.block-container {padding:1.1rem .8rem 3rem;}.terminal-hero,.noctis-watch-hero,.beginner-hero {padding:24px 20px;}.stTabs [data-baseweb="tab"] {padding:.55rem .7rem;font-size:.72rem;}}

/* Distinct alternative-market visual identity */
.alt-sidebar-tag {font-size:10px;letter-spacing:1.7px;font-weight:800;color:#FDE68A;padding:7px 0 11px;}
.alt-hero {border-radius:22px;padding:35px;margin:8px 0 26px;background:radial-gradient(ellipse at 85% 10%,#7041A055,transparent 52%),linear-gradient(125deg,#12252A,#1B1325 65%,#13131A);border:1px solid #CDAF56;box-shadow:0 0 32px #B47AFF20;}
.alt-eyebrow {color:#FFE57D;font-size:11px;letter-spacing:2.8px;font-weight:800;}
.alt-title {font-family:'Space Grotesk',sans-serif;font-size:clamp(28px,4.5vw,51px);font-weight:800;letter-spacing:-1.5px;color:#FFF;margin:12px 0;line-height:1.12;}
.alt-title span {color:#D8AEFF;text-shadow:0 0 22px #B47AFF66;}
.alt-sub {color:#DFD9E7;max-width:740px;line-height:1.6;}
</style>
""", unsafe_allow_html=True)

# Alternative-market research pages. These use public source links rather than
# scraping third-party discussions or claiming to have live sportsbook feeds.
def alternative_market_overview():
    st.markdown("""<div class='alt-hero'><div class='alt-eyebrow'>✦ NOCTIS / ALTERNATIVE MARKETS</div>
    <div class='alt-title'>EXPLORE <span>BEYOND STOCKS</span></div>
    <div class='alt-sub'>Collectibles, sports information, prediction markets and gaming-site research — in one dedicated workspace.</div></div>""", unsafe_allow_html=True)
    a, b, c = st.columns(3)
    with a:
        with st.container(border=True):
            st.markdown("### ⚡ Pokémon Market")
            st.write("Look up card sets, compare published price references and research completed sales.")
            if st.button("Explore Pokémon", use_container_width=True):
                st.session_state.noctis_alt_navigation = "Pokémon Card Market"
                st.rerun()
    with b:
        with st.container(border=True):
            st.markdown("### 🏟️ Sports & Predictions")
            st.write("Find sports statistics, public prediction markets and probability explainers.")
            if st.button("Explore sports", use_container_width=True):
                st.session_state.noctis_alt_navigation = "Sportsbook & Prediction Research"
                st.rerun()
    with c:
        with st.container(border=True):
            st.markdown("### 🎲 Gaming Research")
            st.write("Review public licensing, site information and odds mathematics.")
            if st.button("Explore research", use_container_width=True):
                st.session_state.noctis_alt_navigation = "Gambling Site Research"
                st.rerun()
    st.info("Price references and external websites can change. This hub does not place wagers or guarantee live odds.")


def community_links_page(category):
    titles = {
        "pokemon": ("POKÉMON COMMUNITY", "Card collecting, grading, recent sales and trading-card discussion"),
        "sports": ("SPORTS & PREDICTION FORUMS", "Sports statistics, fan discussion and public prediction-market research"),
        "gambling": ("GAMBLING RESEARCH FORUMS", "Consumer experiences, site safety, regulatory information and responsible play"),
    }
    title, subtitle = titles[category]
    st.markdown(f"<div class='alt-hero'><div class='alt-eyebrow'>✦ NOCTIS / COMMUNITY RESEARCH</div><div class='alt-title'>{html.escape(title)}</div><div class='alt-sub'>{html.escape(subtitle)}</div></div>", unsafe_allow_html=True)
    q = st.text_input("SEARCH DISCUSSION TOPIC", value={"pokemon":"Charizard PSA 10", "sports":"NBA odds", "gambling":"site licensing"}[category], key=f"alt_forum_{category}")
    search = quote_plus(q.strip() or category)
    if category == "pokemon":
        links = [
            ("Reddit / Pokémon TCG", f"https://www.reddit.com/r/PokemonTCG/search/?q={search}&restrict_sr=1&sort=new"),
            ("Reddit / Pokémon Card Value", f"https://www.reddit.com/r/PokemonCardValue/search/?q={search}&restrict_sr=1&sort=new"),
            ("eBay completed sales", f"https://www.ebay.com/sch/i.html?_nkw={search}&LH_Sold=1&LH_Complete=1"),
            ("PriceCharting search", f"https://www.pricecharting.com/search-products?type=prices&q={search}"),
        ]
    elif category == "sports":
        links = [
            ("Reddit / Sportsbook discussions", f"https://www.reddit.com/r/sportsbook/search/?q={search}&restrict_sr=1&sort=new"),
            ("Reddit / Sports discussions", f"https://www.reddit.com/r/sports/search/?q={search}&restrict_sr=1&sort=new"),
            ("ESPN schedules & scores", "https://www.espn.com/"),
            ("Sports Reference historical statistics", "https://www.sports-reference.com/"),
            ("Kalshi public event markets", "https://kalshi.com/markets"),
            ("Polymarket public event markets", "https://polymarket.com/"),
        ]
    else:
        links = [
            ("Reddit / Gambling discussions", f"https://www.reddit.com/r/gambling/search/?q={search}&restrict_sr=1&sort=new"),
            ("American Gaming Association — state regulations", "https://www.americangaming.org/state-of-play/"),
            ("National Council on Problem Gambling", "https://www.ncpgambling.org/"),
        ]
    st.caption("Opens external public pages. Posts are not imported or verified by NOCTIS; links may require sign-in.")
    for label, url in links:
        with st.container(border=True):
            left, right = st.columns([3,1])
            left.markdown(f"**{label}**")
            right.link_button("Open discussion ↗", url, use_container_width=True)
    with st.expander("How to evaluate community claims", expanded=True):
        st.write("Check publication date, original sources, and potential conflicts of interest. Opinions and screenshots do not establish accurate market prices or reliable predictions.")



# NOCTIS Info: educational resources are curated, not a live news or social feed.
NOCTIS_RESEARCH_LINKS = [
    ("Investor.gov — Investing Basics", "Stocks", "Official investor education covering ownership, diversification and investment risks.", "https://www.investor.gov/introduction-investing"),
    ("SEC EDGAR — Company Filings", "Stocks", "Search company annual reports (10-K), quarterly reports (10-Q), and disclosures.", "https://www.sec.gov/edgar/search/"),
    ("FINRA — Investor Education", "Stocks", "Brokerage accounts, order types, margin, and investing protections.", "https://www.finra.org/investors"),
    ("Investor.gov — Day Trading", "Day Trading", "Understand short-term trading risk before trading with real money.", "https://www.investor.gov/introduction-investing/investing-basics/glossary/day-trading"),
    ("FINRA — Frequent Intraday Trading", "Day Trading", "Rules, cash-account considerations, and margin-trading risks.", "https://www.finra.org/investors/investing/investment-products/stocks/day-trading"),
    ("Cboe — Options Institute", "Options", "Educational resources on options, contracts, and risk.", "https://www.cboe.com/optionsinstitute/"),
    ("Bitcoin.org — Getting Started", "Crypto", "Wallets, transactions, network basics, and security concepts.", "https://bitcoin.org/en/getting-started"),
    ("Bitcoin Developer Guides", "Crypto", "More technical detail on blocks, transactions, and wallet mechanics.", "https://developer.bitcoin.org/devguide/"),
    ("CFTC — Digital Assets", "Crypto", "Regulatory resources and warnings about digital asset markets.", "https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/DigitalAssets.html"),
    ("Federal Reserve — FRED", "Macro", "Economic time series such as inflation, rates, and employment.", "https://fred.stlouisfed.org/"),
    ("BLS — Economic Data", "Macro", "Official employment, inflation, and wage statistics.", "https://www.bls.gov/"),
    ("Economic Calendar — Trading Economics", "Macro", "Upcoming economic releases; verify times and values at the primary source.", "https://tradingeconomics.com/calendar"),
]


def noctis_info_home():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / KNOWLEDGE CENTER</div><div class="terminal-title">NOCTIS <span>INFO</span></div><div class="terminal-sub">One organized place for lessons, day-trading research, Bitcoin education, market videos, community conversations and research tools.</div></div>', unsafe_allow_html=True)
    a, b, c = st.columns(3)
    a.metric("LEARNING TRACKS", "5")
    b.metric("CURATED RESOURCES", str(len(NOCTIS_RESEARCH_LINKS)))
    c.metric("RESEARCH TOOLS", "3")
    st.info("Start with a topic below, then choose its page from the NOCTIS Info sidebar. External posts and videos are third-party content, not verified trade signals.")
    for title, summary in [
        ("📘 Stocks for Beginners", "Ten beginner-friendly lessons with hands-on exercises."),
        ("⚡ Trading & Crypto Academy", "Day trading, chart reading, Bitcoin, risk management and options fundamentals."),
        ("▶ Market Videos & Live", "Public market video feeds, YouTube searches, and an embedded player."),
        ("💬 Trader Forums", "Search discussions for a specific stock ticker and follow original threads."),
        ("📚 Research Library", "Filter vetted educational and official research sources by topic."),
        ("🧮 Trading Calculators", "Plan position sizes, risk/reward and simple percentage returns."),
    ]:
        with st.expander(title):
            st.write(summary)
    st.caption("NOCTIS Info is a research library, not a broker or financial advisor.")


def noctis_trading_academy():
    st.markdown("## ⚡ TRADING & CRYPTO ACADEMY")
    st.caption("Five learning tracks • concise lessons • practice prompts")
    tracks = {
        "Day Trading": [
            ("How day trading works", "Day traders open and close positions during the same session, attempting to benefit from short-term moves. Execution costs, volatility and slippage matter.", "Observe one ticker's open, high, low and close for five sessions without trading."),
            ("Risk per trade", "Decide how much capital you can afford to lose before choosing position size. A stop order is not a guarantee of the final execution price.", "Use the position-size calculator with a hypothetical $100 maximum loss."),
            ("Market sessions and liquidity", "US equities typically have regular, premarket and after-hours sessions. Liquidity and spreads can differ significantly outside regular hours.", "Compare price action around the market open with midday trading."),
            ("Rules and account types", "Cash and margin accounts have different restrictions. Intraday margin rules have changed and may be subject to brokerage transition periods; confirm current requirements with your broker.", "Read the FINRA day-trading guidance in the Research Library."),
        ],
        "Technical Analysis": [
            ("Candles and trend", "A candle displays open, high, low and close. Trend lines and support/resistance are interpretations, not predictions.", "Identify a prior high and low on a daily chart."),
            ("Volume", "Volume measures traded shares or units during a period. A volume spike alone does not reveal whether buyers or sellers will win.", "Compare the volume on two large price-move days."),
            ("Moving averages, RSI and MACD", "Moving averages smooth price history; RSI and MACD summarize momentum. All are lagging indicators and can produce false signals.", "Open Technical Analysis and compare RSI with the actual chart."),
        ],
        "Bitcoin & Crypto": [
            ("What Bitcoin is", "Bitcoin is a decentralized network that records transactions in a shared blockchain. Its market price is volatile and may trade 24/7.", "Look up BTC-USD in the Crypto Terminal and inspect the volume."),
            ("Wallets and private keys", "A wallet manages keys that authorize transactions. Losing keys or sending to the wrong address can lead to permanent loss.", "Compare custodial and self-custody wallet tradeoffs."),
            ("Crypto market structure", "Spot, perpetual futures and leveraged products differ in liquidation, fees and counterparty risk. Avoid assuming every crypto venue has the same protections.", "List the risks of a hypothetical leveraged trade."),
        ],
        "Options Basics": [
            ("Calls and puts", "A call gives the holder a right to buy; a put gives a right to sell, under specified terms. Premiums and expiration matter.", "Explain why an option can expire worthless even when the stock moved."),
            ("Volatility and time decay", "Option prices reflect factors including underlying price, time remaining, implied volatility and interest rates.", "Read an options-chain explanation before considering any strategy."),
        ],
        "Long-Term Investing": [
            ("Diversification", "A diversified portfolio spreads company-specific risk but cannot eliminate broad-market losses.", "Compare a single stock with a broad index ETF."),
            ("Fundamental research", "Review business models, cash flow, debt, valuation and company filings rather than relying on a price chart alone.", "Find a 10-K using SEC EDGAR."),
        ],
    }
    track = st.selectbox("CHOOSE A LEARNING TRACK", list(tracks), key="noctis_academy_track")
    st.progress((list(tracks).index(track) + 1) / len(tracks), text=f"Track {list(tracks).index(track) + 1} of {len(tracks)}")
    for index, (title, body, practice) in enumerate(tracks[track], 1):
        with st.expander(f"{index:02d}  {title}", expanded=index == 1):
            st.write(body)
            st.markdown(f"**TRY THIS:** {practice}")
    st.warning("Educational examples only. Short-term trading, margin, derivatives and cryptocurrencies can result in significant losses.")


def noctis_research_library():
    st.markdown("## 📚 NOCTIS RESEARCH LIBRARY")
    st.caption("Curated sources with direct links to their original websites. These are not automatically refreshed articles.")
    a, b = st.columns([1, 2])
    with a:
        category = st.selectbox("TOPIC", ["All", "Stocks", "Day Trading", "Options", "Crypto", "Macro"], key="noctis_library_topic")
    with b:
        search = st.text_input("SEARCH RESOURCES", placeholder="e.g. margin, Bitcoin, inflation", key="noctis_library_search").lower().strip()
    filtered = [r for r in NOCTIS_RESEARCH_LINKS if (category == "All" or r[1] == category) and (not search or search in " ".join(r[:3]).lower())]
    st.caption(f"Showing {len(filtered)} of {len(NOCTIS_RESEARCH_LINKS)} resources")
    if not filtered:
        st.info("No matches. Try another topic or a shorter search.")
    for idx, (title, topic, description, url) in enumerate(filtered):
        with st.container(border=True):
            st.markdown(f"**{title}**  ·  `{topic}`")
            st.write(description)
            st.link_button("Open original source ↗", url)
    st.caption("Verify publication dates and current rules with the linked sources.")


def noctis_trading_calculators():
    st.markdown("## 🧮 TRADING CALCULATORS")
    st.caption("Hypothetical arithmetic only • not trading recommendations")
    tab1, tab2, tab3 = st.tabs(["POSITION SIZE", "RISK / REWARD", "RETURN %"])
    with tab1:
        capital = st.number_input("Account value ($)", min_value=0.0, value=10000.0, step=100.0, key="nc_capital")
        risk_pct = st.number_input("Maximum risk per trade (%)", min_value=0.1, max_value=100.0, value=1.0, step=0.1, key="nc_risk_pct")
        entry = st.number_input("Hypothetical entry ($)", min_value=0.01, value=100.0, key="nc_entry")
        stop = st.number_input("Hypothetical stop ($)", min_value=0.0, value=95.0, key="nc_stop")
        risk_dollars = capital * risk_pct / 100
        unit_risk = abs(entry - stop)
        if unit_risk > 0:
            shares = int(risk_dollars // unit_risk)
            affordable = int(capital // entry)
            st.metric("Maximum whole units (cash-funded estimate)", f"{min(shares, affordable):,}")
            st.caption(f"Risk budget ${risk_dollars:,.2f}; per-unit price difference ${unit_risk:,.2f}. Excludes fees, gaps, slippage, and leverage.")
        else:
            st.warning("Entry and stop must differ.")
    with tab2:
        r_entry = st.number_input("Entry price", value=100.0, min_value=0.01, key="nc_rr_entry")
        r_stop = st.number_input("Stop price", value=95.0, min_value=0.0, key="nc_rr_stop")
        r_target = st.number_input("Target price", value=110.0, min_value=0.0, key="nc_rr_target")
        risk = abs(r_entry - r_stop)
        if risk:
            st.metric("Hypothetical reward-to-risk ratio", f"{abs(r_target - r_entry) / risk:.2f}:1")
            st.caption("This does not measure the probability of reaching the target. Confirm that stop and target are on the intended sides of entry.")
        else:
            st.warning("Entry and stop must differ.")
    with tab3:
        buy = st.number_input("Purchase price", value=100.0, min_value=0.01, key="nc_buy")
        sell = st.number_input("Sale price", value=112.0, min_value=0.0, key="nc_sell")
        units = st.number_input("Units", value=10.0, min_value=0.0, key="nc_units")
        st.metric("Hypothetical percentage return", f"{(sell / buy - 1) * 100:+.2f}%")
        st.metric("Hypothetical gross P/L", f"${(sell - buy) * units:+,.2f}")
        st.caption("Before taxes, trading fees and financing costs.")

@st.fragment(run_every="300s")
def alt_research_refresh():
    st.caption("⟳ Research panel checked at " + datetime.now().strftime("%H:%M:%S") + " local time. Links are not live data feeds.")
    st.caption("Pokémon price lookup caches results for 15 minutes; stock volume refreshes separately in its own page. Sportsbook odds are not automatically imported.")


# Home preferences are local to this Python installation, not an online user account.
HOME_PREF_PATH = Path(__file__).resolve().with_name("noctis_home_preferences.json")
HOME_DEFAULTS = {"city": "Austin", "timezone": "America/Chicago", "stocks": "", "crypto": "", "cards": "", "sports": "", "notes": "", "visible_categories": "stocks,crypto,cards,sports", "quick_launch": "Trading Terminal,NOCTIS Info,Pokémon Market", "home_sections": "Choose Market,Daily Briefing,Community Lounge,Research Pins,Quick Launch"}


def load_home_prefs():
    profiles = load_local_profiles()
    active = account_profile_key()
    raw = profiles.get(active, {})
    return {**HOME_DEFAULTS, **{k: str(v) for k, v in raw.items() if k in HOME_DEFAULTS}}


def save_home_prefs(data):
    profiles = load_local_profiles()
    active = account_profile_key()
    profiles[active] = {k: str(v) for k, v in data.items() if k in HOME_DEFAULTS}
    return save_local_profiles(profiles)


@st.cache_data(ttl=1200, show_spinner=False)
def get_home_forecast(city):
    # Open-Meteo's public geocoder and forecast endpoints; no API key required.
    place_url = "https://geocoding-api.open-meteo.com/v1/search?" + urlencode({"name": city, "count": 1, "language": "en", "format": "json"})
    req = Request(place_url, headers={"User-Agent": "NOCTIS/1.0"})
    with urlopen(req, timeout=7) as resp:
        places = json_storage.loads(resp.read(100000))
    matches = places.get("results") or []
    if not matches:
        raise ValueError("City not found. Try a city name such as Austin or Denver.")
    place = matches[0]
    forecast_url = "https://api.open-meteo.com/v1/forecast?" + urlencode({
        "latitude": place["latitude"], "longitude": place["longitude"],
        "current": "temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m",
        "temperature_unit": "fahrenheit", "wind_speed_unit": "mph", "timezone": "auto", "forecast_days": 1,
    })
    req = Request(forecast_url, headers={"User-Agent": "NOCTIS/1.0"})
    with urlopen(req, timeout=7) as resp:
        result = json_storage.loads(resp.read(100000))
    return place, result.get("current", {})


@st.cache_data(ttl=1800, show_spinner=False)
def noctis_briefing_headlines(topic):
    """Read public Google News RSS headlines, not a personalized tracking service."""
    from urllib.parse import urlencode
    query = topic[:75] + " finance OR news"
    url = "https://news.google.com/rss/search?" + urlencode({"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"})
    req = Request(url, headers={"User-Agent":"NOCTIS/1.0"})
    with urlopen(req, timeout=6) as response:
        payload = response.read(250000)
    root = ET.fromstring(payload)
    results = []
    for item in root.findall("./channel/item")[:5]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if title and link.startswith("https://"):
            results.append((title[:150],link))
    return results


def noctis_briefing_recommendation(prefs):
    """Show one actual public headline related to saved interests; never fabricate media."""
    import random
    fields = (("stocks", "Stocks & ETFs"), ("crypto", "Crypto"),
              ("cards", "Pokémon cards"), ("sports", "Sports"))
    pins = [(value.strip(), category) for field, category in fields
            for value in str(prefs.get(field, "")).split(",") if value.strip()]
    st.markdown("<div class='v27-discovery-kicker'>✦ FOR YOUR RADAR</div>", unsafe_allow_html=True)
    # The choice remains stable across Streamlit widget reruns, but changes when Home is re-entered.
    if "noctis_radar_choice" not in st.session_state:
        topic, category = random.choice(pins) if pins else ("stock market", "Market discovery")
        try:
            stories = noctis_briefing_headlines(topic)
        except (OSError, TimeoutError, ValueError, ET.ParseError):
            stories = []
        selected = random.choice(stories) if stories else None
        st.session_state["noctis_radar_choice"] = (topic, category, selected)
    topic, category, selected = st.session_state["noctis_radar_choice"]
    st.markdown("**" + html.escape(topic) + "**")
    st.caption(category + " · Featured for you")
    if selected:
        title, link = selected
        st.link_button("📰 " + title[:90] + " ↗", link, use_container_width=True)
        st.caption("One featured public article. Source content is not verified by NOCTIS.")
    else:
        st.caption("No current public article available for this topic. Try again on your next visit.")


@st.fragment(run_every="60s")
def noctis_home_clock(timezone):
    try:
        now = datetime.now(ZoneInfo(timezone))
        st.markdown("<div class='v27-clock-art'>◷ <span>LOCAL TIME</span></div>",unsafe_allow_html=True)
        st.metric("LOCAL TIME", now.strftime("%I:%M %p"))
        st.caption(now.strftime("%A, %B %d, %Y") + " · " + now.strftime("%Z"))
    except (KeyError, ValueError):
        st.warning("Invalid time zone in Home settings.")


# v23 personal appearance preference: local-only, separate from existing profile and cloud data.
NOCTIS_APPEARANCE_PATH = Path(__file__).resolve().with_name("noctis_appearance_v23.json")
NOCTIS_THEME_PRESETS = {
    "Original NOCTIS (default)": None,
    "Emerald green": "#16A34A",
    "Ocean blue": "#2563EB",
    "Electric cyan": "#0891B2",
    "Ruby red": "#DC2626",
    "Sunset orange": "#EA580C",
    "Royal purple": "#9333EA",
    "Hot pink": "#DB2777",
    "Custom color": "custom",
}

def noctis_appearance_key():
    sess=st.session_state.get("noctis_cloud_session") or {}
    if sess.get("user_id"):
        return "cloud:" + str(sess["user_id"])
    account=st.session_state.get("noctis_account") or {}
    return "local:" + str(account.get("id") or "guest")

def noctis_load_appearance():
    try:
        data=json_storage.loads(NOCTIS_APPEARANCE_PATH.read_text(encoding="utf-8"))
        entry=data.get(noctis_appearance_key(), {})
        if isinstance(entry,dict): return entry
    except (OSError,ValueError,TypeError,AttributeError):
        pass
    return {}

def noctis_save_appearance(preset,custom):
    try:
        data=json_storage.loads(NOCTIS_APPEARANCE_PATH.read_text(encoding="utf-8"))
        if not isinstance(data,dict): data={}
    except (OSError,ValueError,TypeError):
        data={}
    data[noctis_appearance_key()]={"preset":preset,"custom":custom}
    NOCTIS_APPEARANCE_PATH.write_text(json_storage.dumps(data,indent=2),encoding="utf-8")

def noctis_theme_css():
    preference=noctis_load_appearance()
    preset=preference.get("preset","Original NOCTIS (default)")
    color=NOCTIS_THEME_PRESETS.get(preset)
    if color == "custom": color=preference.get("custom","#16A34A")
    if not color or not re.fullmatch(r"#[0-9a-fA-F]{6}",str(color)):
        return # Absolutely no overrides for the original NOCTIS palette.
    import colorsys
    rgb=tuple(int(color[i:i+2],16) for i in (1,3,5))
    # Dark tinted surfaces keep text readable while changing the entire hub's hue.
    dark=tuple(round(x*.12) for x in rgb)
    medium=tuple(round(x*.23) for x in rgb)
    surface=f"#{dark[0]:02x}{dark[1]:02x}{dark[2]:02x}"
    panel=f"#{medium[0]:02x}{medium[1]:02x}{medium[2]:02x}"
    accent=color
    st.markdown(f"""<style>
    .stApp {{background:radial-gradient(ellipse at 80% 0%, {panel}, transparent 58%), {surface}!important;}}
    [data-testid="stSidebar"] {{background:linear-gradient(180deg,{panel},{surface})!important;border-right:1px solid {accent}!important;}}
    [data-testid="stMetric"], [data-testid="stVerticalBlockBorderWrapper"] > div[data-testid="stVerticalBlock"],
    [data-testid="stExpander"] {{border-color:{accent}88!important;}}
    div[data-testid="stPopover"] button, div[data-testid="stButton"] button,
    div[data-testid="stFormSubmitButton"] button {{border-color:{accent}!important;}}
    div[data-testid="stButton"] button[kind="primary"],
    div[data-testid="stFormSubmitButton"] button[kind="primary"] {{background:{accent}!important;}}
    .noctis-home-hero, .noctis-watch-hero {{background:linear-gradient(110deg,{panel},{surface})!important;border-color:{accent}!important;}}
    .noctis-home-hero span, .noctis-watch-hero span, a {{color:{accent}!important;}}
    .st-key-noctis_global_home_button button, .st-key-noctis_global_profile_button button {{background:{panel}!important;border-color:{accent}!important;color:#ffffff!important;box-shadow:0 0 14px {accent}55!important;}}
    </style>""",unsafe_allow_html=True)

HOME_SECTION_CATALOG = {
        "Daily Briefing": ("🌤️", "Local conditions and your daily research discovery", None),
        "Choose Market": ("◈", "Trading and alternative market entry points", None),
        "Research Pins": ("★", "Your saved stocks, crypto, cards and sports interests", None),
        "Community Lounge": ("🎱", "Open the Billiards Lounge community", None),
        "Quick Launch": ("🚀", "Your personalized shortcut collection", None),
        "Trading Terminal": ("📈", "Stock market overview and charting", ("📈 Trading & Crypto", "📊 Market Terminal", "Trading Terminal")),
        "Crypto Terminal": ("₿", "Digital asset research", ("📈 Trading & Crypto", "📊 Market Terminal", "Crypto Terminal")),
        "Technical Analysis": ("📊", "Technical indicators and market analysis", ("📈 Trading & Crypto", "📊 Market Terminal", "Technical Analysis")),
        "Market Volume": ("▥", "Volume research and market activity", ("📈 Trading & Crypto", "📊 Market Terminal", "Market Volume")),
        "Stock Research": ("🔎", "Company and ticker research", ("📈 Trading & Crypto", "📊 Market Terminal", "Stock Research")),
        "My Watchlist": ("⭐", "Your personal saved watchlist", ("📈 Trading & Crypto", "★ My Watchlist", "My Watchlist")),
        "NOCTIS Info": ("✦", "The dedicated trading information hub", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Info Home")),
        "Stocks for Beginners": ("📗", "Learn stock market fundamentals", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Stocks for Beginners")),
        "Trading & Crypto Academy": ("📚", "Guides and learning resources", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Trading & Crypto Academy")),
        "Market Videos & Live": ("▶️", "Market videos and live research", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Market Videos & Live")),
        "Trader Forums": ("💬", "Trading discussion destinations", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Trader Forums")),
        "Research Library": ("📖", "Research tools and references", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Research Library")),
        "Trading Calculators": ("🧮", "Trading math and calculators", ("📈 Trading & Crypto", "✦ NOCTIS Info", "Trading Calculators")),
        "Alternative Market Overview": ("◈", "Alternative asset research", ("⚡ Alternative Markets", "", "Alternative Market Overview")),
        "Pokémon Card Market": ("⚡", "Pokémon card research", ("⚡ Alternative Markets", "", "Pokémon Card Market")),
        "Pokémon Community": ("🎴", "Pokémon research community", ("⚡ Alternative Markets", "", "Pokémon Community")),
        "Sportsbook & Prediction Research": ("🏟️", "Sports predictions and odds research", ("⚡ Alternative Markets", "", "Sportsbook & Prediction Research")),
        "Sports & Prediction Forums": ("🏆", "Sports prediction discussions", ("⚡ Alternative Markets", "", "Sports & Prediction Forums")),
        "Gambling Site Research": ("🎲", "Gambling site research and information", ("⚡ Alternative Markets", "", "Gambling Site Research")),
        "Gambling Research Forums": ("🗣️", "Gambling research discussion resources", ("⚡ Alternative Markets", "", "Gambling Research Forums")),
    }

def noctis_home_layout_settings():
    prefs = load_home_prefs()
    home_catalog = HOME_SECTION_CATALOG
    selected_sections = [x.strip() for x in prefs.get("home_sections", HOME_DEFAULTS["home_sections"]).split(",") if x.strip() in home_catalog]
    st.markdown("### ★ YOUR HOME, YOUR WAY")
    st.caption("Customize your Command Center without changing its market-first layout.")
    with st.expander("⚙ CUSTOMIZE HOME LAYOUT", expanded=False):
        st.markdown("<div class='v28-config-label'>01 / LOCATION & WEATHER</div>", unsafe_allow_html=True)
        left, right = st.columns([1.05, 1.7], gap="large")
        with left:
            with st.container(border=True):
                st.markdown("**🌤️ Location & Weather**")
                st.caption("Your local conditions, city, and time zone.")
                city = st.text_input("Weather city", value=prefs["city"], max_chars=80, key="v28_home_city")
                zones = ["America/Chicago","America/New_York","America/Denver","America/Los_Angeles","America/Phoenix","America/Anchorage","Pacific/Honolulu","UTC"]
                tz = st.selectbox("Time zone", zones, index=zones.index(prefs["timezone"]) if prefs["timezone"] in zones else 0, key="v28_home_tz")
                if st.button("SAVE LOCATION", key="v28_save_location", use_container_width=True):
                    updated = dict(prefs)
                    updated.update({"city":city.strip() or "Austin", "timezone":tz})
                    if save_home_prefs(updated): st.rerun()
                    else: st.error("Couldn't save location.")
        with right:
            with st.container(border=True):
                st.markdown("**🧩 Dashboard Sections**")
                st.caption("Choose optional destinations from across NOCTIS. Your core Command Center sections stay in place.")
                choices = st.multiselect("Show on my Home", list(home_catalog), default=selected_sections, key="v28_home_sections")
                a,b=st.columns(2)
                if a.button("SAVE HOME LAYOUT", key="v28_save_home_sections", use_container_width=True, type="primary"):
                    updated=dict(prefs)
                    updated["home_sections"]=",".join(choices)
                    if save_home_prefs(updated): st.rerun()
                    else: st.error("Couldn't save Home layout.")
                if b.button("RESTORE STARTER LAYOUT", key="v28_restore_home", use_container_width=True):
                    updated=dict(prefs)
                    updated["home_sections"]=HOME_DEFAULTS["home_sections"]
                    if save_home_prefs(updated): st.rerun()
                    else: st.error("Couldn't restore layout.")
        st.caption("Sections are saved to your local profile. This does not delete watchlists, posts, or existing pinned interests.")


def noctis_settings_page():
    st.markdown("### ⚙ SETTINGS")
    st.caption("Personalize NOCTIS. Your original theme is preserved and can be restored instantly.")
    st.markdown("#### 🎨 Dashboard & Lounge appearance")
    st.write("Pick an accent theme for your hub, sidebar, Command Center, and community. This only changes how your dashboard looks; it never modifies your posts, messages, or original design files.")
    pref=noctis_load_appearance()
    choices=list(NOCTIS_THEME_PRESETS)
    preset=st.selectbox("Color theme",choices,index=choices.index(pref.get("preset")) if pref.get("preset") in choices else 0,key="v23_theme_select")
    custom=st.color_picker("Custom color",value=pref.get("custom","#16A34A"),key="v23_custom_color") if preset=="Custom color" else pref.get("custom","#16A34A")
    a,b=st.columns(2)
    if a.button("APPLY COLOR",key="v23_apply_theme",use_container_width=True):
        try:
            noctis_save_appearance(preset,custom)
            st.rerun()
        except OSError as exc: st.error("Unable to save appearance: "+str(exc))
    if b.button("RESTORE ORIGINAL COLORS",key="v23_reset_theme",use_container_width=True):
        try:
            noctis_save_appearance("Original NOCTIS (default)",custom)
            st.rerun()
        except OSError as exc: st.error("Unable to save appearance: "+str(exc))
    st.caption("Theme is saved on this computer for the currently signed-in account (or guest).")
    st.divider()
    noctis_home_layout_settings()

def noctis_profile_page():
    st.markdown("### ◉ MY PROFILE")
    st.caption("Your identity, account access, community settings and notifications — separate from Command Center.")
    online=cloud_session()
    local=active_account()
    with st.container(border=True):
        st.markdown("#### 🎮 IDENTITY")
        st.write("**Online:** "+(html.escape(online.get("email") or "Signed in") if online else "Not signed in"))
        st.write("**Local:** "+("@"+html.escape(local["username"]) if local else "Guest"))
    tabs=st.tabs(["☁️ Online Profile","🎮 Local Profile","🔔 Local Alerts"])
    with tabs[0]:
        cloud_account_panel()
    with tabs[1]:
        home_account_panel()
        social_profile_editor()
    with tabs[2]:
        social_notifications()

def noctis_home_page():
    prefs = load_home_prefs()
    st.markdown("""<style>
    .v27-weather-icon{font-size:3.1rem;line-height:1.25;filter:drop-shadow(0 6px 15px #fac75c45);padding:4px 0 9px}
    .v27-clock-art{font-size:2.7rem;line-height:1.15;color:#a3cfff;text-shadow:0 0 23px #4c83d366;margin:2px 0 13px}
    .v27-clock-art span{font-size:.69rem;letter-spacing:.18em;color:#aebcce;vertical-align:middle;margin-left:8px}
    .v27-discovery-kicker{font-size:.72rem;font-weight:800;letter-spacing:.13em;color:#d3b9f7;margin-bottom:10px}
    .noctis-home-hero{background:radial-gradient(circle at 84% 22%,#32645a80,transparent 39%),radial-gradient(circle at 14% 90%,#623b8755,transparent 52%),linear-gradient(125deg,#141c29,#14151e)!important;border:1px solid #718ba455!important}
    .noctis-home-hero:after{content:'✧  ◈  ✧';float:right;color:#9fc6b7;letter-spacing:18px;font-size:26px;opacity:.55}
    </style>""",unsafe_allow_html=True)
    st.markdown("""<div class='noctis-home-hero'><div class='home-kicker'>✦ THE PERSONAL MARKET DESK</div><div class='home-heading'>NOCTIS <span>COMMAND CENTER</span></div><div class='home-sub'>Your intelligence desk. Choose a market and get straight to research.</div></div>""", unsafe_allow_html=True)

    st.markdown("""<style>
    .noctis-home-hero{padding:21px 27px!important;border-radius:23px!important;box-shadow:0 20px 55px #0007,inset 0 1px 0 #ffffff15!important}
    .home-heading{font-size:clamp(1.9rem,4vw,3.15rem)!important;letter-spacing:.035em!important}
    .st-key-v25_quick_edit button{min-height:46px!important}
    .v25-dashboard-kicker{padding:13px 18px;border:1px solid #665083;border-radius:16px;background:linear-gradient(115deg,#221831,#101922);margin:14px 0 18px;box-shadow:0 9px 26px #0004}
    .v25-dashboard-kicker strong{color:#d7b7ff;font-size:14px;letter-spacing:.06em}
    .v25-dashboard-kicker span{color:#b4becd;font-size:12px}
    .v25-market-hint{padding:13px 16px;border-left:3px solid #9069cf;background:#1b1725;border-radius:9px;margin:9px 0 15px;color:#d9d3e2;font-size:13px}
    .st-key-v25_quick_edit button{border-radius:999px!important}
    </style>""",unsafe_allow_html=True)
    st.markdown("<div class='v25-dashboard-kicker'><strong>✦ YOUR INTELLIGENCE DESK</strong> &nbsp; <span>Markets · Research · Community · Personal workspace</span></div>",unsafe_allow_html=True)
    st.caption("ACTIVE IDENTITY · " + ("@" + active_account()["username"] if active_account() else "Guest"))
    st.caption("Manage your account, gamertag and community identity in ◉ My Profile.")
    st.markdown("""<style>
    .v28-config-label{font-size:.76rem;font-weight:800;letter-spacing:.13em;color:#a9d9c9;margin:23px 0 13px;padding:9px 13px;border-left:3px solid #59b9a3;background:linear-gradient(90deg,#18342f88,transparent);border-radius:6px}
    .st-key-v28_save_home_sections button{border-radius:12px!important;min-height:44px!important}
    </style>""",unsafe_allow_html=True)
    home_catalog = HOME_SECTION_CATALOG
    selected_sections = [x.strip() for x in prefs.get("home_sections", HOME_DEFAULTS["home_sections"]).split(",") if x.strip() in home_catalog]
    # Primary navigation and daily briefing are always at the top, regardless of saved v28 order.
    # Older saved layouts are preserved; only the visual placement is normalized.
    primary_sections = ["Choose Market", "Daily Briefing"]
    # Fixed, uncluttered Home order; custom destination links remain optional below the essentials.
    optional_sections = ["Community Lounge", "Research Pins"]
    extra_destinations = [x for x in selected_sections if x not in primary_sections + optional_sections + ["Quick Launch"]]
    if not selected_sections:
        noctis_notice("Your Home has no sections selected. Go to Settings → Your Home, Your Way to add sections.","empty_home_layout")
    for section in primary_sections + optional_sections + extra_destinations:
        if section == "Choose Market":
            st.markdown("### ◈ CHOOSE YOUR MARKET")
            st.caption("Open a workspace below. Your Home layout and pins stay saved to the selected local profile.")
            market_a, market_b = st.columns(2, gap="medium")
            with market_a:
                with st.container(border=True):
                    st.markdown("#### 📈 Trading & Crypto")
                    st.caption("Stocks · Bitcoin · technical analysis · NOCTIS Info")
                    st.button("ENTER TRADING →", key="home_enter_trading", use_container_width=True,
                              on_click=choose_market, args=("📈 Trading & Crypto",))
            with market_b:
                with st.container(border=True):
                    st.markdown("#### ⚡ Alternative Markets")
                    st.caption("Pokémon cards · sports predictions · research")
                    st.button("ENTER ALTERNATIVE →", key="home_enter_alternative", use_container_width=True,
                              on_click=choose_market, args=("⚡ Alternative Markets",))

        elif section == "Daily Briefing":
            st.markdown("### ◈ YOUR DAILY BRIEFING")
            st.caption("Local conditions and one fresh research lead, selected around your interests.")
            c1, c2, c3 = st.columns([1, 1.1, 1], gap="medium")
            with c1:
                with st.container(border=True):
                    noctis_home_clock(prefs["timezone"])
            with c2:
                with st.container(border=True):
                    st.markdown("**◈ LOCAL WEATHER**")
                    try:
                        place, current = get_home_forecast(prefs["city"])
                        code = int(current.get("weather_code", -1))
                        condition = "Clear" if code == 0 else "Cloudy" if code in (1,2,3) else "Rain" if code in (51,53,55,61,63,65,80,81,82) else "Snow" if code in (71,73,75,77,85,86) else "Storms" if code in (95,96,99) else "Variable"
                        weather_icon = "☀️" if code == 0 else "⛅" if code in (1,2,3) else "🌧️" if code in (51,53,55,61,63,65,80,81,82) else "❄️" if code in (71,73,75,77,85,86) else "⛈️" if code in (95,96,99) else "🌤️"
                        st.markdown(f"<div class='v27-weather-icon'>{weather_icon}</div>",unsafe_allow_html=True)
                        st.metric(prefs["city"], f"{float(current['temperature_2m']):.0f}°F")
                        st.caption(f"{condition} · Feels {float(current.get('apparent_temperature',0)):.0f}°F · Wind {float(current.get('wind_speed_10m',0)):.0f} mph")
                    except (OSError, ValueError, KeyError, TypeError, TimeoutError):
                        st.info("Weather temporarily unavailable.")
            with c3:
                with st.container(border=True):
                    noctis_briefing_recommendation(prefs)

        elif section == "Research Pins":
            # Research pins are secondary; keep the dashboard concise unless requested.
            total_pins = sum(len([x for x in str(prefs.get(k, "")).split(",") if x.strip()]) for k in ("stocks", "crypto", "cards", "sports"))
            with st.expander(f"★ Research Pins · {total_pins} saved  —  click to manage", expanded=False):
                st.caption("Add or remove tracked interests here. This panel stays collapsed while you navigate markets.")
                category_meta = [("stocks", "📈 Stocks / ETFs", "Ticker, e.g. NVDA"), ("crypto", "₿ Crypto", "Ticker, e.g. BTC-USD"), ("cards", "⚡ Pokémon cards", "Card name"), ("sports", "🏟️ Sports / predictions", "Team or league")]
                cols = st.columns(4, gap="small")
                for col, (field, title, hint) in zip(cols, category_meta):
                    with col:
                        st.markdown("**" + title + "**")
                        items = [x.strip() for x in str(prefs.get(field, "")).split(",") if x.strip()]
                        if not items: st.caption("None saved")
                        for idx, item in enumerate(items):
                            left, right = st.columns([5, 1], gap="small", vertical_alignment="center")
                            left.caption(item)
                            if right.button("×", key=f"v29_unpin_{field}_{idx}", help="Remove pin"):
                                updated = dict(prefs)
                                updated[field] = ", ".join(x for n, x in enumerate(items) if n != idx)
                                if save_home_prefs(updated): st.rerun()
                        with st.form("v29_pin_" + field, clear_on_submit=True):
                            new = st.text_input("Add", placeholder=hint, key="v29_pin_input_" + field, label_visibility="collapsed")
                            if st.form_submit_button("+ Add", use_container_width=True):
                                clean = new.strip().replace(",", " ")[:80]
                                if clean and clean.casefold() not in [x.casefold() for x in items]:
                                    updated = dict(prefs)
                                    updated[field] = ", ".join(items + [clean])
                                    if save_home_prefs(updated): st.rerun()
                                else: st.warning("Enter a new interest.")
        elif section == "Community Lounge":
            with st.container(border=True):
                st.markdown("#### 🎱 THE BILLIARDS LOUNGE")
                st.caption("Community posts, discussions, friends, messages and notifications.")
                st.button("OPEN THE LOUNGE →",key="v28_lounge_card",use_container_width=True,on_click=noctis_open_lounge)
        elif section == "Quick Launch":
            # The full editable Quick Launch block is rendered below when selected.
            pass
        else:
            icon, description, destination = home_catalog[section]
            if destination:
                with st.expander(icon + " " + section, expanded=False):
                    st.caption(description)
                    st.button("OPEN " + section + " →", key="v29_open_" + re.sub(r"[^a-z0-9]", "_", section.lower()), on_click=noctis_go_to, args=destination)
    if True:  # Quick Launch always sits above Home customization.
        st.markdown("### ✦ QUICK LAUNCH")
        st.caption("Your shortcuts start with useful defaults. Customize which destinations appear without changing your market navigation.")
        quick_targets = {
            "Trading Terminal": ("📈 Trading & Crypto", "📊 Market Terminal", "Trading Terminal", "📈"),
            "Crypto Terminal": ("📈 Trading & Crypto", "📊 Market Terminal", "Crypto Terminal", "₿"),
            "Technical Analysis": ("📈 Trading & Crypto", "📊 Market Terminal", "Technical Analysis", "📊"),
            "Market Volume": ("📈 Trading & Crypto", "📊 Market Terminal", "Market Volume", "▥"),
            "Stock Research": ("📈 Trading & Crypto", "📊 Market Terminal", "Stock Research", "🔎"),
            "My Watchlist": ("📈 Trading & Crypto", "★ My Watchlist", "My Watchlist", "★"),
            "NOCTIS Info": ("📈 Trading & Crypto", "✦ NOCTIS Info", "Info Home", "✦"),
            "Trading Academy": ("📈 Trading & Crypto", "✦ NOCTIS Info", "Trading & Crypto Academy", "📚"),
            "Pokémon Market": ("⚡ Alternative Markets", "", "Pokémon Card Market", "⚡"),
            "Alternative Overview": ("⚡ Alternative Markets", "", "Alternative Market Overview", "◈"),
        }
        saved_quick = [x.strip() for x in prefs.get("quick_launch", "").split(",") if x.strip() in quick_targets]
        with st.expander("⚙ EDIT QUICK LAUNCH", expanded=False):
            st.caption("Choose up to six shortcuts. They will be saved with your Home layout.")
            selection = st.multiselect("Quick Launch destinations", list(quick_targets), default=saved_quick, max_selections=6, key="v25_quick_selection")
            if st.button("SAVE QUICK LAUNCH", key="v25_quick_save", use_container_width=True):
                updated = dict(prefs)
                updated["quick_launch"] = ",".join(selection)
                if save_home_prefs(updated): st.rerun()
                else: st.error("Couldn't save your shortcuts.")
            if st.button("RESTORE DEFAULT SHORTCUTS", key="v25_quick_restore"):
                updated = dict(prefs)
                updated["quick_launch"] = "Trading Terminal,NOCTIS Info,Pokémon Market"
                if save_home_prefs(updated): st.rerun()
                else: st.error("Couldn't restore shortcuts.")
        if saved_quick:
            for index in range(0,len(saved_quick),3):
                columns = st.columns(3, gap="medium")
                for column, name in zip(columns,saved_quick[index:index+3]):
                    space, group, destination, symbol = quick_targets[name]
                    with column:
                        st.button(symbol + "  " + name + " →", key="v25_quick_"+name.replace(" ","_"),use_container_width=True,on_click=noctis_go_to,args=(space,group,destination))
        else:
            noctis_notice("No shortcuts selected. Open Edit Quick Launch to add destinations.","empty_quick_launch")
        st.caption("Local profiles are not user accounts. Pins are research shortcuts, not positions or real-time quotes. Do not use shared/cloud deployment for private profile data.")



if market_space == "⚡ Alternative Markets" and page != "Home":
    st.markdown("""<style>
    .stApp {background:radial-gradient(ellipse at 85% 5%,#29133B,transparent 42%),radial-gradient(ellipse at 0% 90%,#102C31,transparent 50%),#0B0D13!important;}
    [data-testid="stSidebar"] {background:linear-gradient(180deg,#1A1427,#101A1D)!important;border-right:1px solid #765A8D!important;}
    [data-testid="stMetric"] {border-color:#75604B!important;}
    </style>""", unsafe_allow_html=True)

# Sticky top-right command center button stays visible while scrolling.
st.markdown("""<style>
.st-key-noctis_global_home_button {position:fixed!important;top:0.65rem;right:1.5rem;z-index:999999;width:190px;max-width:42vw;filter:drop-shadow(0 3px 13px rgba(150,85,250,.24));}
.st-key-noctis_global_home_button button {background:#20152f!important;border:1px solid #A66AFF!important;color:#F2E9FF!important;border-radius:999px!important;font-weight:800!important;box-shadow:0 0 14px rgba(169,106,255,.22)!important;}
@media(max-width:720px){.st-key-noctis_global_home_button{right:.65rem;top:.35rem;width:145px;}.st-key-noctis_global_home_button button{font-size:11px!important;}}
</style>""", unsafe_allow_html=True)
# Global Home action lives at the top-right of the main workspace, not in the sidebar.
with st.container():
    st.button("⌂  COMMAND CENTER", key="noctis_global_home_button", use_container_width=True,
              on_click=noctis_open_home, type="secondary")

st.markdown("""<style>
.st-key-noctis_global_profile_button {position:fixed!important;top:3.7rem;right:1.5rem;z-index:999998;width:190px;max-width:42vw;}
.st-key-noctis_global_profile_button button {background:#20152f!important;border:1px solid #A66AFF!important;color:#F2E9FF!important;border-radius:999px!important;font-weight:800!important;}
@media(max-width:720px){.st-key-noctis_global_profile_button{right:.65rem;top:3.2rem;width:145px;}.st-key-noctis_global_profile_button button{font-size:11px!important;}}
</style>""",unsafe_allow_html=True)
with st.container():
    st.button("◉  MY PROFILE", key="noctis_global_profile_button", use_container_width=True,
              on_click=noctis_open_profile, type="secondary")
# Load theme after existing market-specific CSS so user choice overrides it.
noctis_theme_css()

st.markdown("""<style>.v25-market-guide{background:linear-gradient(120deg,#1e182b,#111c22);border:1px solid #56476a;border-radius:15px;padding:17px 20px;margin:14px 0 19px}.v25-market-guide strong{color:#d8c0ff;letter-spacing:.07em}.v25-market-guide p{color:#b8c3cd;margin:7px 0 0;font-size:13px}</style>""",unsafe_allow_html=True)
st.markdown("<div style='color:#B8A5CE;font-size:11px;font-weight:800;letter-spacing:2.8px;margin:0 0 6px'>✦ NOCTIS / MARKET INTELLIGENCE</div>", unsafe_allow_html=True)
st.caption("LOCAL RESEARCH TERMINAL  •  DELAYED MARKET DATA  •  PAPER TRADING")
if page != "Home":
    st.session_state.pop("noctis_radar_choice", None)
if page == "Home":
    noctis_home_page()
elif page == "My Profile":
    noctis_profile_page()
elif page == "Settings":
    noctis_settings_page()
elif page == "Billiards Lounge":
    lounge_page()
elif page == "Trading Terminal":
    st.markdown("<div class='v25-market-guide'><strong>📈 TRADING TERMINAL</strong><p>Explore price action and paper-trading tools. Candles show open, high, low and close; volume measures traded shares. Historical data may be delayed.</p></div>",unsafe_allow_html=True)
    trading_terminal()
elif page == "Crypto Terminal":
    st.markdown("<div class='v25-market-guide'><strong>₿ CRYPTO TERMINAL</strong><p>Research crypto charts and indicators. Moving averages smooth price trends; RSI measures recent momentum, not guaranteed future direction.</p></div>",unsafe_allow_html=True)
    technical_analysis_page(default_crypto=True)
elif page == "Technical Analysis":
    st.markdown("<div class='v25-market-guide'><strong>📊 TECHNICAL ANALYSIS</strong><p>Use multiple indicators for context, not certainty. Compare trend, momentum, volatility, and volume before drawing conclusions.</p></div>",unsafe_allow_html=True)
    technical_analysis_page(default_crypto=False)
elif page == "Market Volume":
    market_volume_page()
elif page == "Stock Research":
    trading_asset_workspace()
elif page == "Trader Forums":
    trader_forums_page()
elif page == "Info Home":
    noctis_info_home()
elif page == "Trading & Crypto Academy":
    noctis_trading_academy()
elif page == "Research Library":
    noctis_research_library()
elif page == "Trading Calculators":
    noctis_trading_calculators()
elif page == "My Watchlist":
    watchlist_page()
elif page == "Stocks for Beginners":
    beginner_guide()
elif page == "Market Videos & Live":
    market_videos()
elif page == "Alternative Market Overview":
    alternative_market_overview()
elif page == "Pokémon Card Market":
    pokemon_market_page()
    alt_research_refresh()
elif page == "Pokémon Community":
    community_links_page("pokemon")
elif page == "Sportsbook & Prediction Research":
    sportsbook_research_page()
    alt_research_refresh()
elif page == "Sports & Prediction Forums":
    community_links_page("sports")
elif page == "Gambling Research Forums":
    community_links_page("gambling")
else:
    gambling_research()
    alt_research_refresh()
