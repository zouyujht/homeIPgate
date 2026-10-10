#!/usr/bin/env python3
"""
SOCKS5 节点检测流水线
=====================
流程:
  1. 从 v2rayse API 获取 Shadowsocks 节点
  2. 解析 base64 编码的节点信息
  3. 去重
  4. 并发调用检测 Worker
  5. 生成 public/socks5.txt
"""

import base64
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, urlparse, parse_qs

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# SOCKS5 节点源 (多个源支持回退)
SOCKS5_SOURCES = [
    "https://raw.githubusercontent.com/v2rayse/v2rayseApi/master/v2rayse.json",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/ss-sub.txt",
]

WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://check5.zouyu.dpdns.org/check?socks5=")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# edgetunnel 入口地址池（与 SSTP 共享）
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "saas.sin.fan:443,cdn.204910.best:443,www.mfyx.cn:443,p.etime.vip:443,cdn.ctn32.us.kg:443,cf.877774.xyz:443,spring.io:443,"
        "cf.nyanya.moe:443,www.sloomb.com:443,op.chinwa.eu.cc:443,www.leics.police.uk:443,securecircle.com:443,www.shopify.com:443,"
        "www.carousell.sg:443,www.dbs.com.sg:443,openai.com:443,linear.app:443,www.bilibili.com:443,uspto.gov:443,www.vmware.com:443",
    ).split(",")
    if h.strip()
]

SOCKS5_NODES_URL = os.environ.get("SOCKS5_NODES_URL", "https://zouyujht.github.io/homeIPgate/socks5.txt")

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_socks5_nodes():
    """从 v2rayse 等源获取 SOCKS5 节点"""
    for source_url in SOCKS5_SOURCES:
        try:
            log("SOCKS5 SOURCE", f"尝试获取: {source_url}")
            resp = requests.get(source_url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            
            # 尝试按 JSON 解析（v2rayse API）
            if source_url.endswith('.json'):
                try:
                    data = resp.json()
                    nodes = parse_v2rayse_json(data)
                    if nodes:
                        log("SOCKS5 SOURCE", f"从 v2rayse JSON 获取 {len(nodes)} 个节点")
                        return nodes, "v2rayse-json"
                except (json.JSONDecodeError, ValueError):
                    pass
            
            # 尝试按 base64 行格式解析
            lines = resp.text.strip().split('\n')
            nodes = parse_ss_lines(lines)
            if nodes:
                log("SOCKS5 SOURCE", f"从 {source_url.split('/')[-1]} 获取 {len(nodes)} 个节点")
                return nodes, f"ss-lines"
        except Exception as exc:
            log("SOCKS5 SOURCE", f"源失败: {exc}")
    
    die("所有 SOCKS5 源均不可用")

def parse_v2rayse_json(data):
    """解析 v2rayse JSON 格式"""
    nodes = []
    if not isinstance(data, dict):
        return nodes
    
    # v2rayse 返回的结构: {"configVersion": 2, "proxies": [...]}
    proxies = data.get("proxies") or []
    for p in proxies:
        if p.get("type") != "ss":  # 只要 Shadowsocks
            continue
        
        host = p.get("server") or p.get("host")
        port = p.get("port")
        name = p.get("name") or ""
        
        if not host or not port:
            continue
        
        # 尝试从名称中提取国家信息
        country_code, country = extract_country_from_name(name)
        
        nodes.append({
            "host": str(host),
            "port": int(port),
            "country": country,
            "country_code": country_code,
            "protocol": "socks5",
            "name": name,
        })
    
    return nodes

def parse_ss_lines(lines):
    """解析 base64 编码的 SS 节点行（ss://... 格式）"""
    nodes = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or not line.startswith('ss://'):
            continue
        
        try:
            node = parse_ss_url(line)
            if node:
                nodes.append(node)
        except Exception:
            continue
    
    return nodes

def parse_ss_url(url):
    """解析单条 ss:// URL"""
    # ss://method:password@host:port#remarks
    if not url.startswith('ss://'):
        return None
    
    url = url[5:]  # 去掉 ss://
    
    # 分离 remarks（#后面的部分）
    remarks = ""
    if '#' in url:
        url, remarks = url.rsplit('#', 1)
        remarks = remarks.strip()
    
    # 解析主体
    if '@' not in url:
        # 可能是 base64 编码格式：ss://base64(method:password@host:port)#remarks
        try:
            # 补全 base64 padding
            padding = (4 - len(url) % 4) % 4
            url_padded = url + '=' * padding
            decoded = base64.b64decode(url_padded).decode('utf-8')
            if '@' in decoded:
                url = decoded
            else:
                return None
        except Exception:
            return None
    
    # 现在应该有 @
    if '@' not in url:
        return None
    
    method_pass, host_port = url.rsplit('@', 1)
    
    # 解析 host:port
    if ':' not in host_port:
        return None
    
    # 处理 IPv6
    if host_port.startswith('['):
        if ']:' in host_port:
            host, port_str = host_port.rsplit(']:', 1)
            host = host[1:]  # 去掉 [
        else:
            return None
    else:
        parts = host_port.rsplit(':', 1)
        if len(parts) != 2:
            return None
        host, port_str = parts
    
    try:
        port = int(port_str)
    except ValueError:
        return None
    
    if not (1 <= port <= 65535):
        return None
    
    country_code, country = extract_country_from_name(remarks)
    
    return {
        "host": host,
        "port": port,
        "country": country,
        "country_code": country_code,
        "protocol": "socks5",
        "name": remarks,
    }

def extract_country_from_name(name):
    """从节点名称提取国家信息"""
    if not name:
        return "?", "未知"
    
    name_upper = name.upper()
    
    # 常见国家代码和名称映射
    country_map = {
        "JP": "日本", "US": "美国", "SG": "新加坡", "KR": "韩国", "TW": "台湾",
        "HK": "香港", "CA": "加拿大", "AU": "澳大利亚", "GB": "英国", "DE": "德国",
        "FR": "法国", "NL": "荷兰", "RU": "俄罗斯", "IN": "印度", "BR": "巴西",
    }
    
    # 尝试匹配国家代码
    for code, country in country_map.items():
        if code in name_upper or country in name:
            return code, country
    
    # 尝试匹配英文国家名
    for code, country in COUNTRY_ZH.items():
        if country in name:
            return code, country
    
    return "?", "未知"

def dedupe(nodes):
    """去重"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "socks5")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    return "unknown"

def check_one(node, session):
    """检测单个节点"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_all(nodes, session):
    """并发检测所有节点"""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, source):
    """生成统计数据"""
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)
    
    stats = {
        "raw_nodes": raw_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter": sum(1 for n in available if n["residential"] == "datacenter"),
        "unknown": sum(1 for n in available if n["residential"] == "unknown"),
    }
    
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp
    
    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "protocol": "socks5",
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

def build_socks5_text(data):
    """生成纯节点行版本: 每行 = 入口地址#名字$socks5://..."""
    countries = data["countries"]
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS
    
    lines = []
    idx = 0
    ordered = sorted(countries.items(), key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(grp["nodes"], key=lambda n: (0 if n.get("residential") == "residential" else 1, n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or ""))
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$socks5://{n['host']}:{n['port']}")
        
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$socks5://{n['host']}:{n['port']}")
    
    return "\n".join(lines) + "\n"

def write_outputs(data):
    """输出数据文件"""
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    
    # 生成 JSON 数据
    data_path = os.path.join(PUBLIC_DIR, "socks5_data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    
    # 生成节点文本文件
    nodes_path = os.path.join(PUBLIC_DIR, "socks5.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_socks5_text(data))
    
    return data_path, nodes_path

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    nodes, source = fetch_socks5_nodes()
    raw_count = len(nodes)
    
    if raw_count == 0:
        die("没有获取到任何 SOCKS5 节点")
    
    uniq = dedupe(nodes)
    
    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]
    
    log("SOCKS5 NODES", f"获取原始节点: {raw_count}")
    log("SOCKS5 NODES", f"去重后: {len(uniq)}")
    
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0
    
    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]
    
    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")
    
    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用")
    
    data = build_outputs(results, raw_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")
    
    data_path, nodes_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"在 edgetunnel 后台使用: {SOCKS5_NODES_URL}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
