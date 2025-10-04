#!/usr/bin/env python3
"""
Alist Tree Crawler - 递归遍历Alist网站文件系统并生成树形结构输出

支持并发请求、错误重试、实时输出等功能
"""

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, quote

import aiohttp
import aiofiles


class AlistTreeCrawler:
    def __init__(self, site_url: str, max_depth: int = 30, output_file: str = "tree.log",
                 max_retries: int = 20, tps_limit: int = 5, break_threshold: int = 2000,
                 break_duration: int = 8, start_path: str = "/", password: str = ""):
        self.site_url = site_url.rstrip('/')
        self.max_depth = max_depth
        self.output_file = output_file
        self.max_retries = max_retries
        self.tps_limit = tps_limit
        self.break_threshold = break_threshold
        self.break_duration = break_duration
        self.start_path = start_path.strip() if start_path.strip() else "/"
        self.password = password

        # 并发控制
        self.semaphore = asyncio.Semaphore(tps_limit)
        self.session: Optional[aiohttp.ClientSession] = None

        # 状态跟踪
        self.visited_paths: Set[str] = set()
        self.output_file_handle = None

        # 统计信息
        self.total_requests = 0
        self.failed_requests = 0
        self.processed_items = 0
        self.continuous_processed_count = 0

    async def __aenter__(self):
        """异步上下文管理器入口"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100)
        )
        self.output_file_handle = await aiofiles.open(self.output_file, 'w', encoding='utf-8')
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        if self.session:
            await self.session.close()
        if self.output_file_handle:
            await self.output_file_handle.close()

    async def make_api_request(self, path: str) -> Optional[Dict]:
        """
        发送API请求到Alist /api/fs/list接口

        Args:
            path: 要查询的路径

        Returns:
            API响应数据，失败时返回None
        """
        url = urljoin(self.site_url, '/api/fs/list')
        headers = {
            'Authorization': '',  # 公开网站，置空
            'Content-Type': 'application/json'
        }
        payload = {
            'path': path,
            'password': self.password,
            'page': 1,
            'per_page': 0,  # 获取所有项目
            'refresh': False
        }

        async with self.semaphore:  # 限制并发数
            last_error_message = ""
            for attempt in range(self.max_retries):
                try:
                    self.total_requests += 1
                    async with self.session.post(url, headers=headers, json=payload) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('code') == 200:
                                return data.get('data')
                            else:
                                last_error_message = data.get('message', 'Unknown error')
                                print(f"API错误 {path}: {last_error_message} (尝试 {attempt + 1}/{self.max_retries})")
                        else:
                            print(f"HTTP错误 {path}: {response.status} (尝试 {attempt + 1}/{self.max_retries})")

                except Exception as e:
                    print(f"请求异常 {path} (尝试 {attempt + 1}/{self.max_retries}): {e}")

                if attempt < self.max_retries - 1:
                    # 针对 object not found 错误使用递增间隔
                    if "object not found" in last_error_message.lower():
                        retry_delay = min(5 * (attempt + 1), 120)
                    else:
                        retry_delay = 2
                    await asyncio.sleep(retry_delay)

            self.failed_requests += 1
            print(f"请求失败，已达最大重试次数: {path}")
            return None

    async def validate_start_path(self) -> bool:
        """
        验证起始路径是否存在

        Returns:
            bool: 路径是否存在
        """
        print(f"验证起始路径: {self.start_path}")
        data = await self.make_api_request(self.start_path)
        if data is None:
            return False

        # 检查是否成功获取到路径内容
        if 'content' not in data:
            return False

        print(f"起始路径验证成功")
        return True

    async def take_break(self):
        """
        执行休息，防止服务器过载
        """
        print(f"\n已连续处理 {self.continuous_processed_count} 个项目，休息 {self.break_duration} 秒以防止服务器过载...")

        for remaining in range(self.break_duration, 0, -1):
            print(f"\r休息中... {remaining} 秒后继续", end="", flush=True)
            await asyncio.sleep(1)

        print("\r休息完成，继续处理..." + " " * 20)
        self.continuous_processed_count = 0

    async def write_tree_item(self, name: str, is_dir: bool, depth: int, is_last: bool = False):
        """
        写入树形结构项目到输出文件

        Args:
            name: 文件/目录名
            is_dir: 是否为目录
            depth: 当前深度
            is_last: 是否为同级最后一项
        """
        indent = "    " * depth  # 每层4个空格缩进
        type_indicator = "[DIR]" if is_dir else "[FILE]"
        line = f"{indent}{name} {type_indicator}\n"

        await self.output_file_handle.write(line)
        await self.output_file_handle.flush()  # 实时写入
        self.processed_items += 1
        self.continuous_processed_count += 1

    async def crawl_directory(self, path: str, depth: int = 0) -> List[str]:
        """
        爬取指定目录

        Args:
            path: 目录路径
            depth: 当前深度

        Returns:
            子目录路径列表
        """
        if depth > self.max_depth or path in self.visited_paths:
            return []

        self.visited_paths.add(path)

        print(f"正在处理 (深度 {depth}): {path}")

        # 获取目录内容
        data = await self.make_api_request(path)
        if not data or 'content' not in data:
            return []

        content = data['content']
        if not content:
            return []

        # 分离文件和目录，按名称排序
        directories = []
        files = []

        for item in content:
            if item.get('is_dir', False):
                directories.append(item)
            else:
                files.append(item)

        directories.sort(key=lambda x: x.get('name', ''))
        files.sort(key=lambda x: x.get('name', ''))

        # 记录本次处理前的计数
        items_before = self.continuous_processed_count

        # 先输出所有文件
        for file_item in files:
            name = file_item.get('name', 'Unknown')
            await self.write_tree_item(name, False, depth)

        # 再输出所有目录
        subdirs = []
        for dir_item in directories:
            name = dir_item.get('name', 'Unknown')
            await self.write_tree_item(name, True, depth)

            # 构建子目录完整路径
            if path.endswith('/'):
                subdir_path = path + name
            else:
                subdir_path = path + '/' + name
            subdirs.append(subdir_path)

        # 检查是否需要休息（在处理完当前API响应的所有内容后）
        items_processed_this_request = self.continuous_processed_count - items_before
        if items_processed_this_request > 0 and self.continuous_processed_count >= self.break_threshold:
            await self.take_break()

        return subdirs

    async def crawl_recursive(self):
        """递归爬取整个文件系统"""
        print(f"开始爬取: {self.site_url}")
        print(f"起始路径: {self.start_path}")
        print(f"最大深度: {self.max_depth}")
        print(f"输出文件: {self.output_file}")
        print(f"TPS限制: {self.tps_limit}")
        print(f"重试次数: {self.max_retries}")
        print(f"休息机制: 每处理 {self.break_threshold} 个项目休息 {self.break_duration} 秒")
        print("-" * 50)

        # 验证起始路径是否存在
        if not await self.validate_start_path():
            raise ValueError(f"指定的起始路径不存在或无法访问: {self.start_path}")

        # 写入文件头
        header = f"Alist Tree Structure - {self.site_url}\n"
        header += f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"Start Path: {self.start_path}\n"
        header += f"Max Depth: {self.max_depth}\n"
        header += "=" * 60 + "\n\n"
        await self.output_file_handle.write(header)

        # 从指定路径开始，使用队列进行广度优先遍历
        queue = [(self.start_path, 0)]  # (path, depth)

        while queue:
            # 批量处理当前层级
            current_level = []
            next_queue = []

            # 收集当前深度的所有路径
            current_depth = queue[0][1] if queue else 0
            while queue and queue[0][1] == current_depth:
                current_level.append(queue.pop(0))

            # 并发处理当前层级的所有目录
            tasks = []
            for path, depth in current_level:
                if depth <= self.max_depth:
                    tasks.append(self.crawl_directory(path, depth))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # 收集下一层级的目录
                for result in results:
                    if isinstance(result, list):
                        for subdir in result:
                            next_queue.append((subdir, current_depth + 1))

            # 将下一层级添加到队列
            queue.extend(next_queue)

        # 写入统计信息
        footer = f"\n" + "=" * 60 + "\n"
        footer += f"爬取完成\n"
        footer += f"总请求数: {self.total_requests}\n"
        footer += f"失败请求数: {self.failed_requests}\n"
        footer += f"处理项目数: {self.processed_items}\n"
        footer += f"成功率: {((self.total_requests - self.failed_requests) / max(self.total_requests, 1) * 100):.1f}%\n"
        await self.output_file_handle.write(footer)

        print("-" * 50)
        print(f"爬取完成!")
        print(f"总请求数: {self.total_requests}")
        print(f"失败请求数: {self.failed_requests}")
        print(f"处理项目数: {self.processed_items}")
        print(f"输出文件: {self.output_file}")


async def main():
    parser = argparse.ArgumentParser(description='Alist Tree Crawler - 递归遍历Alist文件系统')
    parser.add_argument('--site', required=True, help='Alist网站URL')
    parser.add_argument('--max-depth', type=int, default=30, help='最大递归深度 (默认: 30)')
    parser.add_argument('--out', default='tree.log', help='输出文件名 (默认: tree.log)')
    parser.add_argument('--low-level-retries', type=int, default=20, help='API请求重试次数 (默认: 20)')
    parser.add_argument('--tps', type=int, default=5, help='TPS限制 (默认: 5)')
    parser.add_argument('--break-threshold', type=int, default=2000, help='连续处理项目数阈值，达到后休息 (默认: 2000)')
    parser.add_argument('--break-duration', type=int, default=8, help='休息时长（秒） (默认: 8)')
    parser.add_argument('--path', default='/', help='起始爬取路径 (默认: /)')
    parser.add_argument('--password', default='', help='访问密码 (默认: 空)')

    args = parser.parse_args()

    try:
        async with AlistTreeCrawler(
            site_url=args.site,
            max_depth=args.max_depth,
            output_file=args.out,
            max_retries=args.low_level_retries,
            tps_limit=args.tps,
            break_threshold=args.break_threshold,
            break_duration=args.break_duration,
            start_path=args.path,
            password=args.password
        ) as crawler:
            await crawler.crawl_recursive()

    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序执行出错: {e}")
        raise


if __name__ == '__main__':
    asyncio.run(main())
