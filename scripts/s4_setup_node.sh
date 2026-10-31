#!/usr/bin/env bash
# S4 前端前置：把 apt 源固定到清华镜像（官方 http.kali.org 会重定向到 neusoft，
# 而 neusoft 域名在本机偶发 DNS 解析失败），然后安装 Node.js + npm。
set -e

echo kali | sudo -S -v

echo "==> 1/4 切换 apt 源"
echo 'deb https://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free non-free-firmware' \
    | sudo tee /etc/apt/sources.list > /dev/null

echo "==> 2/4 apt update"
sudo apt-get update -q

echo "==> 3/4 安装 nodejs + npm"
sudo apt-get install -y -q nodejs npm

echo "==> 4/4 版本"
node -v
npm -v
