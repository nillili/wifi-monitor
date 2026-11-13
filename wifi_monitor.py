#!/usr/bin/env python3
"""와이파이 실시간 감시 — http://127.0.0.1:8840

AP가 내보내는 신호를 듣기만 한다(부하 거의 없음).
실행: python3 wifi_monitor.py
"""
import csv
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8840
INTERVAL = 3        # 측정 간격(초)
RESCAN_EVERY = 60   # 주변 AP 다시 찾는 간격(초)
SCAN_WAIT = 6       # 찾기가 끝나기를 기다리는 시간(초)
SYSTEM = platform.system()   # "Linux", "Windows", "Darwin"(맥)
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")  # 1분마다 기록

note_list = []  # 오늘 적은 상황 메모 (과거 → 현재)
day = []        # 오늘 1분 단위 공유기 지연 (아침 → 지금)
state = {"time": "", "me": {}, "aps": [], "history": [], "notes": note_list, "day": day}
history = deque(maxlen=100)
lock = threading.Lock()


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, text=True,
                              encoding="oem" if SYSTEM == "Windows" else None,
                              errors="replace").stdout or ""
    except Exception:
        return ""


def decode_ssid(s):
    try:
        return s.encode("latin1").decode("unicode_escape").encode("latin1").decode("utf8")
    except Exception:
        return s


def channel(freq):
    f = int(float(freq))
    if f == 2484:
        return 14
    return (f - 2407) // 5 if f < 3000 else (f - 5000) // 5


def find_iface():
    m = re.search(r"Interface (\S+)", run(["iw", "dev"]))
    return m.group(1) if m else "wlan0"


def find_gateway():
    if SYSTEM == "Windows":
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)",
                      run(["route", "print", "-4", "0.0.0.0"]), re.M)
    elif SYSTEM == "Darwin":
        m = re.search(r"gateway:\s*(\S+)", run(["route", "-n", "get", "default"]))
    else:
        m = re.search(r"default via (\S+)", run(["ip", "route"]))
    return m.group(1) if m else None


def linux_link(iface):
    out = run(["iw", "dev", iface, "link"])
    me = {}
    m = re.search(r"Connected to (\S+)", out)
    if not m:
        return me
    me["bssid"] = m.group(1)
    for key, pat in [("ssid", r"SSID: (.*)"), ("freq", r"freq: (\S+)"),
                     ("signal", r"signal: (-?\d+)"),
                     ("rx", r"rx bitrate: ([\d.]+)"), ("tx", r"tx bitrate: ([\d.]+)")]:
        m = re.search(pat, out)
        if m:
            me[key] = m.group(1).strip()
    if "ssid" in me:
        me["ssid"] = decode_ssid(me["ssid"])
    if "freq" in me:
        me["channel"] = channel(me["freq"])
    return me


def linux_scan(iface):
    out = run(["iw", "dev", iface, "scan", "dump"])
    result = []
    for block in re.split(r"\n(?=BSS )", out):
        m = re.match(r"BSS ([0-9a-f:]{17})", block)
        if not m:
            continue
        f = re.search(r"freq: (\S+)", block)
        s = re.search(r"signal: (-?[\d.]+)", block)
        n = re.search(r"\n\tSSID: (.*)", block)
        a = re.search(r"last seen: (\d+) ms ago", block)
        if not f or not s:
            continue
        result.append({
            "bssid": m.group(1),
            "ssid": decode_ssid(n.group(1).strip()) if n else "",
            "channel": channel(f.group(1)),
            "band": "2.4GHz" if float(f.group(1)) < 3000 else "5GHz",
            "signal": int(float(s.group(1))),
            "age": int(a.group(1)) // 1000 if a else 0,
        })
    return result


# ---------- 윈도우: netsh 로 읽는다 ----------

def win_fields(out):
    """'이름 : 값' 줄을 (이름, 값) 목록으로 바꾼다."""
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s*(.*?)\s+:\s?(.*)$", line)
        if m:
            rows.append((m.group(1).strip(), m.group(2).strip()))
    return rows


def win_dbm(percent):
    """윈도우는 신호를 %로 준다 → dBm 어림값."""
    return int(percent.rstrip("%")) // 2 - 100


def windows_link():
    me, rssi = {}, None
    for k, v in win_fields(run(["netsh", "wlan", "show", "interfaces"])):
        kl = k.lower()
        if kl == "ssid":
            me["ssid"] = v
        elif kl in ("bssid", "ap bssid"):
            me["bssid"] = v.lower()
        elif kl == "rssi":
            rssi = v
        elif ("채널" in k or "channel" in kl) and v.isdigit():
            me["channel"] = int(v)
        elif "mbps" in kl and ("수신" in k or "receive" in kl):
            me["rx"] = v
        elif "mbps" in kl and ("전송" in k or "송신" in k or "transmit" in kl):
            me["tx"] = v
        elif ("신호" in k or "signal" in kl) and v.endswith("%"):
            me["signal"] = str(win_dbm(v))
    if rssi and re.match(r"-?\d+$", rssi):
        me["signal"] = rssi
    return me if "bssid" in me else {}


def windows_scan():
    result, ssid, cur = [], "", None
    for k, v in win_fields(run(["netsh", "wlan", "show", "networks", "mode=bssid"])):
        kl = k.lower()
        if re.match(r"ssid \d+$", kl):
            ssid, cur = v, None
        elif re.match(r"bssid \d+$", kl):
            cur = {"bssid": v.lower(), "ssid": ssid, "channel": 0, "band": "", "signal": -100, "age": 0}
            result.append(cur)
        elif cur is not None:
            if ("신호" in k or "signal" in kl) and v.endswith("%"):
                cur["signal"] = win_dbm(v)
            elif "밴드" in k or kl == "band":
                cur["band"] = v.replace(" ", "")
            elif ("채널" in k or "channel" in kl) and v.isdigit():
                cur["channel"] = int(v)
                cur["band"] = cur["band"] or ("2.4GHz" if int(v) <= 14 else "5GHz")
    return result


def windows_ping(gw):
    out = run(["ping", "-n", "3", "-w", "1000", gw], timeout=12)
    times = []
    for line in out.splitlines():
        m = re.search(r"[=<]\s*(\d+)\s*ms", line)
        if "TTL" in line.upper() and m:
            times.append(float(m.group(1)))
    if not times:
        return 100, None, None
    return round((3 - len(times)) / 3 * 100), round(sum(times) / len(times), 1), max(times)


# ---------- 맥: system_profiler 로 읽는다 (느려서 1분에 한 번) ----------

mac_me = {}


def mac_entry(net):
    text = str(net.get("spairport_network_channel", ""))
    m = re.match(r"\d+", text)
    ch = int(m.group(0)) if m else 0
    band = "6GHz" if "6GHz" in text else "5GHz" if "5GHz" in text or ch > 14 else "2.4GHz"
    s = re.search(r"-?\d+", str(net.get("spairport_signal_noise", "")))
    ssid = net.get("_name", "")
    bssid = str(net.get("spairport_network_bssid") or "%s ch%s" % (ssid, ch)).lower()
    return {"bssid": bssid, "ssid": ssid, "channel": ch, "band": band,
            "signal": int(s.group(0)) if s else -100, "age": 0}


def mac_scan():
    """주변 AP와 내 연결을 한 번에 읽는다. 맥은 AP 주소를 주지 않아 '이름+채널'로 구분한다."""
    global mac_me
    result, mac_me = [], {}
    try:
        data = json.loads(run(["system_profiler", "SPAirPortDataType", "-json"], timeout=40))
        ifaces = data["SPAirPortDataType"][0]["spairport_airport_interfaces"]
    except Exception:
        return result
    for iface in ifaces:
        cur = iface.get("spairport_current_network_information")
        if cur:
            e = mac_entry(cur)
            rate = str(cur.get("spairport_network_rate", "")) or None
            mac_me = {"bssid": e["bssid"], "ssid": e["ssid"], "channel": e["channel"],
                      "signal": str(e["signal"]), "rx": rate, "tx": rate}
            result.append(e)
        for net in iface.get("spairport_airport_other_local_wireless_networks", []):
            e = mac_entry(net)
            if all(e["bssid"] != o["bssid"] for o in result):
                result.append(e)
    return result


# ---------- 운영체제에 맞는 방법을 고른다 ----------

def read_link(iface):
    if SYSTEM == "Windows":
        return windows_link()
    if SYSTEM == "Darwin":
        return dict(mac_me)
    return linux_link(iface)


def scan_aps(iface):
    if SYSTEM == "Windows":
        return windows_scan()
    if SYSTEM == "Darwin":
        return mac_scan()
    run(["nmcli", "dev", "wifi", "rescan"])
    time.sleep(SCAN_WAIT)  # 찾는 동안에는 지연이 튀므로 끝난 뒤에 잰다
    return linux_scan(iface)


def ping(gw):
    if SYSTEM == "Windows":
        return windows_ping(gw)
    if SYSTEM == "Darwin":
        out = run(["ping", "-c", "3", "-q", gw], timeout=12)
    else:
        out = run(["ping", "-c", "5", "-i", "0.2", "-W", "1", "-q", gw], timeout=8)
    loss = re.search(r"(\d+)(?:\.\d+)?% packet loss", out)
    rtt = re.search(r"= [\d.]+/([\d.]+)/([\d.]+)/", out)
    return (int(loss.group(1)) if loss else 100,
            float(rtt.group(1)) if rtt else None,
            float(rtt.group(2)) if rtt else None)


def internet_ms():
    t = time.time()
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=2).close()
        return round((time.time() - t) * 1000, 1)
    except Exception:
        return None


def ap_key(bssid):
    """한 AP의 2.4GHz·5GHz 주소는 끝자리만 다르다 → 같은 AP로 묶는다."""
    b = bssid.split(":")
    if len(b) != 6 or not re.match(r"[0-9a-f]{1,2}$", b[5]):
        return bssid   # 맥처럼 주소가 없는 경우
    return ":".join(b[:5]) + ":%02x" % (int(b[5], 16) >> 1)


def avg(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else ""


def peak(values):
    values = [v for v in values if v is not None]
    return round(max(values), 1) if values else ""


def append_csv(name, header, rows):
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, "%s_%s.csv" % (name, time.strftime("%Y-%m-%d")))
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerows(rows)


def write_log(minute, samples, aps):
    """1분에 한 줄: 그 1분 동안의 평균·최대값."""
    last = samples[-1]
    with lock:
        day.append({"t": minute[-5:], "ping": peak([s["ping"] for s in samples]) or None})
    append_csv("연결", ["시각", "측정횟수", "연결AP", "채널", "신호평균(dBm)", "신호최저(dBm)",
                       "받기(Mbps)", "보내기(Mbps)", "공유기지연평균(ms)", "공유기지연최대(ms)",
                       "손실평균(%)", "손실최대(%)", "인터넷지연평균(ms)", "인터넷지연최대(ms)",
                       "공유기끊김횟수", "인터넷끊김횟수", "공유기지연_3초최대(ms)"],
               [[minute, len(samples), last.get("ap", ""), last.get("channel", ""),
                 avg([s.get("signal") for s in samples]),
                 min([s["signal"] for s in samples if s.get("signal") is not None], default=""),
                 last.get("rx", ""), last.get("tx", ""),
                 avg([s["ping"] for s in samples]), peak([s["ping_max"] for s in samples]),
                 avg([s["loss"] for s in samples]), peak([s["loss"] for s in samples]),
                 avg([s["internet"] for s in samples]), peak([s["internet"] for s in samples]),
                 sum(1 for s in samples if s["ping"] is None),
                 sum(1 for s in samples if s["internet"] is None),
                 peak([s["ping"] for s in samples])]])
    append_csv("AP", ["시각", "AP", "대역", "채널", "신호(dBm)", "같은채널_우리AP",
                     "같은채널_주변AP", "주소"],
               [[minute, a["ap"], a["band"], a["channel"], a["signal"], a["same_channel_mine"],
                 a["same_channel"] - a["same_channel_mine"], a["bssid"]] for a in aps])


def load_notes():
    """다시 시작해도 오늘 메모 목록이 보이도록 로그 파일에서 읽어 온다."""
    path = os.path.join(LOG_DIR, "메모_%s.csv" % time.strftime("%Y-%m-%d"))
    if not os.path.exists(path):
        return
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in list(csv.reader(f))[1:]:
            if len(row) >= 2:
                note_list.append({"t": row[0][-8:], "text": row[1]})


def load_day():
    """다시 시작해도 아침부터의 그래프가 보이도록 로그 파일에서 읽어 온다.

    그래프 값은 '그 1분 중 가장 높았던 3초 측정값'이다.
    이 칸이 없던 예전 줄은 어림값을 쓴다(평균과 '최대 ÷ 5' 중 큰 값 — 실제보다 낮을 수 있다).
    """
    path = os.path.join(LOG_DIR, "연결_%s.csv" % time.strftime("%Y-%m-%d"))
    if not os.path.exists(path):
        return
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    if rows and len(rows[0]) == 16:   # 예전 파일: 제목 줄에 새 칸 이름을 붙인다
        rows[0].append("공유기지연_3초최대(ms)")
        with open(path + ".tmp", "w", newline="", encoding="utf-8-sig") as f:
            csv.writer(f).writerows(rows)
        os.replace(path + ".tmp", path)
    for row in rows[1:]:
        if len(row) < 10:
            continue
        if len(row) >= 17 and row[16]:
            value = float(row[16])
        elif row[8] and row[9]:
            value = round(max(float(row[8]), float(row[9]) / 5), 1)
        else:
            value = None
        day.append({"t": row[0][-5:], "ping": value})


def add_note(text):
    """상황 메모: 로그 파일에 남기고, 그래프의 지금 위치에 붙인다."""
    append_csv("메모", ["시각", "내용"], [[time.strftime("%Y-%m-%d %H:%M:%S"), text]])
    with lock:
        note_list.append({"t": time.strftime("%H:%M:%S"), "text": text})
        if history:
            last = history[-1]
            last["note"] = (last["note"] + " / " + text) if last.get("note") else text


def collect():
    iface = find_iface() if SYSTEM == "Linux" else ""
    last_scan, scan = 0, []
    samples, minute = [], time.strftime("%Y-%m-%d %H:%M")
    while True:
        gw = find_gateway()
        if time.time() - last_scan > RESCAN_EVERY:
            scan = scan_aps(iface)  # 다음 찾기 전까지 이 목록을 그대로 쓴다
            last_scan = time.time()
        me = read_link(iface)
        loss, ping_avg, ping_max = ping(gw) if gw else (100, None, None)
        me.update({"gateway": gw, "loss": loss, "ping": ping_avg, "ping_max": ping_max,
                   "internet": internet_ms()})

        mine = [b for b in scan if me.get("ssid") and b["ssid"] == me["ssid"]]
        keys = sorted({ap_key(b["bssid"]) for b in mine})
        for b in mine:
            b["ap"] = "AP%d" % (keys.index(ap_key(b["bssid"])) + 1)
            b["same_channel"] = sum(1 for o in scan if o["channel"] == b["channel"]
                                    and o["bssid"] != b["bssid"])
            b["same_channel_mine"] = sum(1 for o in mine if o["channel"] == b["channel"]
                                         and ap_key(o["bssid"]) != ap_key(b["bssid"]))
            b["connected"] = b["bssid"] == me.get("bssid")
        mine.sort(key=lambda b: (b["ap"], b["band"]))

        now = time.strftime("%Y-%m-%d %H:%M")
        if now != minute and samples:
            try:
                write_log(minute, samples, mine)
            except Exception as e:
                print("로그 쓰기 실패:", e)
            samples = []
        minute = now
        samples.append({
            "ap": next((b["ap"] for b in mine if b["connected"]), ""),
            "channel": me.get("channel"), "rx": me.get("rx"), "tx": me.get("tx"),
            "signal": int(me["signal"]) if me.get("signal") else None,
            "ping": ping_avg, "ping_max": ping_max, "loss": loss, "internet": me["internet"]})

        history.append({"t": time.strftime("%H:%M:%S"), "ping": ping_avg, "loss": loss})
        with lock:
            state.update({"time": time.strftime("%H:%M:%S"), "me": me, "aps": mine,
                          "history": list(history)})
        time.sleep(INTERVAL)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Wi-Fi Monitor</title>
<style>
body{font-family:sans-serif;background:#fff;color:#222;margin:20px auto;padding:0 20px 0 70px;max-width:1560px;text-align:center}
h1{font-size:20px} h2{font-size:16px;margin-top:24px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px 10px;text-align:center;font-size:14px}
th{background:#f0f0f0}
.bad{background:#ffd9d9} .warn{background:#fff3c4} .me{font-weight:bold;background:#e2f0ff}
svg{border:1px solid #ccc;width:100%;height:120px;display:block}
#chartbox{position:relative}
#axis div{position:absolute;left:-54px;width:48px;text-align:right;font-size:12px;color:#666}
small{color:#666}
#notes div{position:absolute;top:2px;font-size:12px;color:#b45000;background:rgba(255,255,255,.8);padding:0 4px;white-space:nowrap}
#note{position:fixed;right:12px;bottom:12px;margin:0}
#note input{font-size:14px;padding:4px;width:240px} #note button{font-size:14px;padding:4px 10px}
#xaxis{position:relative;height:22px}
#xaxis div{position:absolute;top:4px;font-size:12px;color:#666;white-space:nowrap}
#wrap{display:flex;gap:30px;align-items:stretch}
#left{width:340px;flex:none} #right{flex:1;min-width:0}
#left,#right{display:flex;flex-direction:column} #left table,#right table{flex:1}
#page{display:flex;gap:30px;align-items:stretch}
#main{flex:1;min-width:0} #side{width:220px;flex:none;display:flex;flex-direction:column}
#logbox{flex:1;position:relative;border:1px solid #ccc;min-height:120px;margin-bottom:22px}
#log{position:absolute;top:0;left:0;right:0;bottom:0;overflow-y:auto;padding:6px 8px;text-align:left;font-size:13px}
#log div{margin-bottom:4px;cursor:pointer} #log span{color:#666}
th[title]{cursor:help}
#me th,#me td,#aps td{white-space:nowrap}
body{font-variant-numeric:tabular-nums}
#charthead{position:relative;display:flow-root}
#tabs{position:absolute;left:0;bottom:0}
#tabs button{font-size:13px;padding:4px 14px;border:1px solid #ccc;border-bottom:none;background:#f0f0f0;cursor:pointer;margin-right:2px}
#tabs button.on{background:#fff;font-weight:bold}
#lang{position:fixed;left:12px;bottom:12px;font-size:14px;padding:4px}
</style></head><body>
<h1><span id="t_title"></span> <small id="time"></small></h1>
<div id="page"><div id="main">
<div id="wrap"><div id="left"><h2 id="t_me"></h2><table id="me"></table></div>
<div id="right"><h2 id="t_aps"></h2><table id="aps"></table></div></div>
<div id="charthead"><div id="tabs"><button id="tab_live"></button><button id="tab_day"></button></div><h2 id="t_chart"></h2></div><div id="chartbox"><div id="axis"></div><div id="notes"></div><svg id="chart" viewBox="0 0 600 120" preserveAspectRatio="none"></svg><div id="xaxis"></div></div>
</div><div id="side"><h2 id="t_log"></h2><div id="logbox"><div id="log"></div></div></div></div>
<form id="note"><input id="notetext" maxlength="100"> <button id="notebtn"></button></form>
<select id="lang"><option value="en">English</option><option value="ko">한국어</option></select>
<script>
const TEXT = {
  en: {title:'Wi-Fi Monitor', me:'My Connection', aps:'AP List', chart:'Router Latency (ms)', tabLive:'Last 5 min', tabDay:'Today',
       name:'Name', channel:'Channel', signal:'Signal', signalGood:'Good: -67 dBm or higher',
       rate:'RX / TX Rate', rateGood:'Higher is better', router:'Router Latency', routerGood:'Good: under 20 ms',
       loss:'Loss', lossGood:'Good: 0%', internet:'Internet Latency', internetGood:'Good: under 50 ms',
       band:'Band', oursShort:'Ours', othersShort:'Others', log:'Notes',
       ours:'Our APs on Same Channel', oursGood:'Good: 0',
       others:'Other APs on Same Channel', othersGood:'Fewer is better', address:'Address',
       down:'Down', none:'Not connected', connected:' (connected)',
       noteBtn:'Add note', notePh:'Situation (e.g. break time)'},
  ko: {title:'와이파이 감시', me:'내 연결', aps:'AP 목록', chart:'공유기 지연 (ms)', tabLive:'최근 5분', tabDay:'오늘 전체',
       name:'이름', channel:'채널', signal:'신호', signalGood:'적정: -67 dBm 이상',
       rate:'받기/보내기 속도', rateGood:'높을수록 좋음', router:'공유기 지연', routerGood:'적정: 20 ms 미만',
       loss:'손실', lossGood:'적정: 0%', internet:'인터넷 지연', internetGood:'적정: 50 ms 미만',
       band:'대역', oursShort:'우리 AP', othersShort:'주변 AP', log:'상황 기록',
       ours:'같은 채널의 우리 AP', oursGood:'적정: 0',
       others:'같은 채널의 주변 AP', othersGood:'적을수록 좋음', address:'주소',
       down:'끊김', none:'연결 안 됨', connected:' (연결됨)',
       noteBtn:'기록', notePh:'상황 입력 (예: 쉬는 시간)'}
};
let lang = 'en';
try { lang = localStorage.getItem('lang') || 'en'; } catch(e){}
if (!TEXT[lang]) lang = 'en';
let T = TEXT[lang];
let view = 'live', D = null, picked = null;   // picked: 목록에서 누른 메모의 시각
function th(label, hint, tip){ return '<th' + (tip ? ' title="' + tip + '"' : '') + '>' + label + (hint ? '<br><small>' + hint + '</small>' : '') + '</th>'; }
function labels(){
  document.documentElement.lang = lang;
  document.title = T.title;
  for (const k of ['title','me','aps','chart','log']) document.getElementById('t_' + k).textContent = T[k];
  document.getElementById('notebtn').textContent = T.noteBtn;
  document.getElementById('tab_live').textContent = T.tabLive;
  document.getElementById('tab_day').textContent = T.tabDay;
  document.getElementById('tab_live').className = view == 'live' ? 'on' : '';
  document.getElementById('tab_day').className = view == 'day' ? 'on' : '';
  document.getElementById('notetext').placeholder = T.notePh;
}
const sel = document.getElementById('lang');
sel.value = lang;
sel.onchange = () => {
  lang = sel.value; T = TEXT[lang];
  try { localStorage.setItem('lang', lang); } catch(e){}
  labels(); tick();
};
document.getElementById('tab_live').onclick = () => { view = 'live'; labels(); drawChart(); };
document.getElementById('tab_day').onclick = () => { view = 'day'; labels(); drawChart(); };
document.getElementById('log').onclick = (e) => {
  const item = e.target.closest('div[data-t]');
  if (!item) return;
  picked = picked == item.dataset.t ? null : item.dataset.t;   // 같은 것을 다시 누르면 지움
  view = 'day'; labels(); drawChart();
};
function esc(t){ const e = document.createElement('div'); e.textContent = t; return e.innerHTML; }
document.getElementById('note').onsubmit = async (e) => {
  e.preventDefault();
  const box = document.getElementById('notetext'), text = box.value.trim();
  if (!text) return;
  try { await fetch('/note', {method: 'POST', body: JSON.stringify({text: text})}); } catch(err){ return; }
  box.value = ''; tick();
};
function cls(v, warn, bad){ return v==null ? 'bad' : v>=bad ? 'bad' : v>=warn ? 'warn' : ''; }
function show(v, unit){ return v==null ? T.down : v + unit; }
async function tick(){
  let d;
  try { d = await (await fetch('/data')).json(); } catch(e){ return; }
  const m = d.me;
  document.getElementById('time').textContent = d.time;
  document.getElementById('me').innerHTML =
    '<tr>' + th(T.name) + '<td>' + (m.ssid||T.none) + '</td></tr>' +
    '<tr>' + th(T.channel) + '<td>' + (m.channel||'-') + '</td></tr>' +
    '<tr>' + th(T.signal, T.signalGood) + '<td class="' + (m.signal < -75 ? 'bad' : m.signal < -67 ? 'warn' : '') + '">' + (m.signal||'-') + ' dBm</td></tr>' +
    '<tr>' + th(T.rate, T.rateGood) + '<td>' + (m.rx||'-') + ' / ' + (m.tx||'-') + ' Mbps</td></tr>' +
    '<tr>' + th(T.router, T.routerGood) + '<td class="' + cls(m.ping,20,50) + '">' + show(m.ping,' ms') + '</td></tr>' +
    '<tr>' + th(T.loss, T.lossGood) + '<td class="' + cls(m.loss,1,5) + '">' + m.loss + '%</td></tr>' +
    '<tr>' + th(T.internet, T.internetGood) + '<td class="' + cls(m.internet,50,100) + '">' + show(m.internet,' ms') + '</td></tr>';
  let h = '<tr>' + th('AP') + th(T.band) + th(T.channel) + th(T.signal, T.signalGood) +
    th(T.oursShort, '', T.ours + ' (' + T.oursGood + ')') + th(T.othersShort, '', T.others + ' (' + T.othersGood + ')') +
    th(T.address) + '</tr>';
  for (const a of d.aps){
    h += '<tr class="' + (a.connected ? 'me' : '') + '"><td>' + a.ap + (a.connected ? T.connected : '') + '</td><td>' + a.band +
      '</td><td>' + a.channel + '</td><td>' + a.signal + ' dBm</td>' +
      '<td class="' + (a.same_channel_mine ? 'bad' : '') + '">' + a.same_channel_mine + '</td>' +
      '<td>' + (a.same_channel - a.same_channel_mine) + '</td><td>' + a.bssid + '</td></tr>';
  }
  document.getElementById('aps').innerHTML = h;
  D = d; drawChart();
  const log = document.getElementById('log');
  if (log.childElementCount != d.notes.length){
    log.innerHTML = d.notes.map(n => '<div data-t="' + n.t + '"><span>' + n.t + '</span> ' + esc(n.text) + '</div>').join('');
    log.scrollTop = log.scrollHeight;
  }
}
function toMin(t){ return +t.slice(0, 2) * 60 + +t.slice(3, 5); }
function drawChart(){
  const d = D;
  if (!d) return;
  const pts = [], ticks = [];
  let pickedX = null;
  if (view == 'live'){            // 최근 5분: 3초마다 한 점
    const last = d.history.length - 1;   // 가장 새 값이 오른쪽 끝, 과거는 왼쪽으로 밀려난다
    d.history.forEach((p, i) => pts.push({x: 600 - (last - i) * 6, v: p.ping, note: p.note}));
    for (let k = 0; k <= 6; k++){
      const back = Math.round((6 - k) * 100 / 6), p = d.history[last - back];
      ticks.push({x: 600 - back * 6, label: p ? p.t : ''});
    }
  } else if (d.day.length){       // 오늘 전체: 1분 평균을 한 점으로, 눈금은 1시간마다
    const mins = d.day.map(p => toMin(p.t)), a = mins[0], b = Math.max(mins[mins.length - 1], a + 1);
    d.day.forEach((p, i) => pts.push({x: (mins[i] - a) / (b - a) * 600, v: p.ping, gap: i > 0 && mins[i] - mins[i - 1] > 2}));
    for (let h = Math.ceil(a / 60); h * 60 <= b; h++)
      ticks.push({x: (h * 60 - a) / (b - a) * 600, label: String(h).padStart(2, '0') + ':00'});
    if (picked){
      const x = (toMin(picked) + +picked.slice(6, 8) / 60 - a) / (b - a) * 600;
      if (x >= 0 && x <= 600) pickedX = x;
    }
  }
  const top = Math.max(30, Math.ceil(Math.max(0, ...pts.filter(p => p.v != null).map(p => p.v)) / 30) * 30);
  let marks = '', axis = '', xaxis = '', notes = '', lines = '', seg = '';
  const poly = s => '<polyline fill="none" stroke="#06c" stroke-width="1.5" points="' + s + '"/>';
  for (let i = 0; i <= 3; i++){
    const y = 115 - i / 3 * 105;
    axis += '<div style="top:' + (y - 8) + 'px">' + (top * i / 3) + ' ms</div>';
    marks += '<line x1="0" x2="600" y1="' + y + '" y2="' + y + '" stroke="#e5e5e5"/>';
  }
  for (const t of ticks){
    marks += '<line x1="' + t.x + '" x2="' + t.x + '" y1="0" y2="120" stroke="#e5e5e5"/>';
    xaxis += '<div style="left:' + (t.x / 6) + '%;transform:translateX(' + (t.x < 20 ? '0' : t.x > 580 ? '-100%' : '-50%') + ')">' + t.label + '</div>';
  }
  for (const p of pts){
    if (p.note){
      marks += '<line x1="' + p.x + '" x2="' + p.x + '" y1="0" y2="120" stroke="#e67700"/>';
      notes += '<div style="left:' + (p.x / 6) + '%;transform:translateX(' + (p.x > 480 ? '-100%' : '0') + ')">' + esc(p.note) + '</div>';
    }
    if ((p.v == null || p.gap) && seg){ lines += poly(seg); seg = ''; }
    if (p.v == null) marks += '<line x1="' + p.x + '" x2="' + p.x + '" y1="0" y2="120" stroke="#e33"/>';
    else seg += p.x + ',' + (115 - p.v / top * 105) + ' ';
  }
  if (seg) lines += poly(seg);
  if (pickedX != null) lines += '<line x1="' + pickedX + '" x2="' + pickedX + '" y1="0" y2="120" stroke="#e00000" stroke-width="3" vector-effect="non-scaling-stroke"/>';
  document.getElementById('axis').innerHTML = axis;
  document.getElementById('xaxis').innerHTML = xaxis;
  document.getElementById('notes').innerHTML = notes;
  document.getElementById('chart').innerHTML = marks + lines;
}
labels(); tick(); setInterval(tick, 3000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/data":
            with lock:
                body = json.dumps(state, ensure_ascii=False).encode()
            ctype = "application/json; charset=utf-8"
        else:
            body = PAGE.encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/note":
            self.send_error(404)
            return
        try:
            size = min(int(self.headers.get("Content-Length", 0)), 2000)
            text = str(json.loads(self.rfile.read(size)).get("text", "")).strip()[:100]
        except Exception:
            text = ""
        if text:
            add_note(text)
        self.send_response(200 if text else 400)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    load_notes()
    load_day()
    threading.Thread(target=collect, daemon=True).start()
    try:
        print("와이파이 감시: http://127.0.0.1:%d" % PORT)
    except Exception:   # 한글을 못 찍는 터미널
        print("Wi-Fi Monitor: http://127.0.0.1:%d" % PORT)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
