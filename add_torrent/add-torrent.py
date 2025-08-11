#!/usr/bin/env python3
import argparse
import os
import sys
import requests
from tqdm import tqdm
import time
import getpass

def parse_arguments():
    parser = argparse.ArgumentParser(description='批量添加torrent文件到qBittorrent')
    parser.add_argument('--address', required=True, help='qBittorrent Web API地址 (http/https://address:port)')
    parser.add_argument('--save-to', required=True, help='下载文件保存的基础路径')
    parser.add_argument('--skip-hash-check', action='store_true', help='跳过哈希校验（用于做种）')
    parser.add_argument('--category', help='添加的torrents的分类(如不指定则自动根据目录结构生成)')
    parser.add_argument('torrent_dir', help='包含torrent文件的目录')
    
    return parser.parse_args()

def find_torrent_files(directory):
    """递归查找指定目录中的所有torrent文件，并返回其绝对路径、相对路径和所属类别"""
    torrent_files = []
    directory = os.path.abspath(directory)  # 确保目录为绝对路径
    root_dirname = os.path.basename(directory)  # 根目录名称
    
    # 用于跟踪每个子目录中的torrent文件
    dir_to_torrents = {}
    
    for root, dirs, files in os.walk(directory):
        torrent_in_current_dir = False
        for file in files:
            if file.endswith('.torrent'):
                abs_path = os.path.join(root, file)
                # 计算相对于torrent_dir的相对路径
                rel_path = os.path.relpath(root, directory)
                if rel_path == '.':  # 如果在根目录，则相对路径为空
                    rel_path = ''
                
                # 记录此种子文件
                torrent_files.append((abs_path, rel_path))
                torrent_in_current_dir = True
                
                # 为目录路径创建条目
                if rel_path not in dir_to_torrents:
                    dir_to_torrents[rel_path] = []
                dir_to_torrents[rel_path].append((abs_path, rel_path))
    
    # 检查是否所有种子都在根目录
    all_in_root = (len(dir_to_torrents.keys()) == 1 and '' in dir_to_torrents)
    
    # 根据目录结构生成分类名
    result_with_category = []
    for abs_path, rel_path in torrent_files:
        if all_in_root:
            # 如果所有种子都在根目录，使用根目录名作为分类
            category = root_dirname
        else:
            # 否则，根据相对路径生成分类名
            if rel_path == '':
                # 根目录中的种子使用根目录名
                category = root_dirname
            else:
                # 将路径转换为分类名，例如"subdir1/subdir2" -> "subdir1_subdir2"
                parts = rel_path.split(os.sep)
                if not parts or parts[0] == '':  # 如果没有剩余部分，使用根目录名
                    category = root_dirname
                else:
                    category = '_'.join(parts)
        
        result_with_category.append((abs_path, rel_path, category))
    
    return result_with_category

def connect_to_qbittorrent(address):
    """连接到qBittorrent API，如需要则处理身份验证"""
    session = requests.Session()
    
    # 规范化地址，确保没有双斜杠
    address = address.rstrip('/')
    
    try:
        # 首先检查是否可以连接
        api_url = f"{address}/api/v2/app/version"
        print(f"正在连接到qBittorrent API: {api_url}")
        response = session.get(api_url)
        print(f"API响应状态码: {response.status_code}")
        
        # 如果成功响应，可以继续
        if response.status_code == 200:
            print(f"已连接到qBittorrent {response.text}")
            return session
            
        # 如果收到403 Forbidden或401 Unauthorized，需要身份验证
        elif response.status_code in [401, 403]:
            print(f"qBittorrent API需要身份验证 (状态码: {response.status_code})")
            username = input("用户名: ")
            password = getpass.getpass("密码: ")
            
            print("正在尝试登录...")
            login_response = session.post(
                f"{address}/api/v2/auth/login",
                data={"username": username, "password": password}
            )
            print(f"登录响应: {login_response.text} (状态码: {login_response.status_code})")
            
            if login_response.text == "Ok." or login_response.status_code == 200:
                print("身份验证成功")
                # 再次尝试获取版本以确认
                version_check = session.get(f"{address}/api/v2/app/version")
                print(f"验证后API响应状态码: {version_check.status_code}")
                if version_check.status_code == 200:
                    print(f"已连接到qBittorrent {version_check.text}")
                    return session
                else:
                    print(f"登录后访问API出错: {version_check.status_code}")
                    print(f"响应内容: {version_check.text}")
                    return None
            else:
                print(f"身份验证失败: {login_response.text}")
                return None
        else:
            print(f"qBittorrent API返回意外响应: {response.status_code}")
            print(f"响应内容: {response.text}")
            print(f"响应头: {dict(response.headers)}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"连接到qBittorrent时出错: {e}")
        return None

def add_torrents(session, address, torrent_files_info, base_save_path, skip_hash_check, user_category):
    """逐个添加torrent文件到qBittorrent并显示进度条，每个torrent使用相应的子目录和分类"""
    success_count = 0
    fail_count = 0
    
    # 规范化地址，确保没有双斜杠
    address = address.rstrip('/')
    
    # 确保基础保存路径为绝对路径
    base_save_path = os.path.abspath(base_save_path)
    
    progress_bar = tqdm(torrent_files_info, desc="添加torrents", unit="个")
    
    for torrent_file, rel_path, auto_category in progress_bar:
        try:
            # 创建完整的保存路径：基础路径 + torrent的相对路径
            full_save_path = os.path.join(base_save_path, rel_path)
            
            with open(torrent_file, 'rb') as f:
                torrent_data = f.read()
            
            files = {'torrents': (os.path.basename(torrent_file), torrent_data, 'application/x-bittorrent')}
            data = {'savepath': full_save_path, 'skip_checking': str(skip_hash_check).lower()}
            
            # 优先使用用户指定的分类，否则使用自动生成的分类
            if user_category:
                data['category'] = user_category
            else:
                data['category'] = auto_category
            
            response = session.post(f"{address}/api/v2/torrents/add", files=files, data=data)
            
            if response.status_code == 200 and response.text == "Ok.":
                success_count += 1
                progress_bar.set_postfix(成功=success_count, 失败=fail_count)
            else:
                fail_count += 1
                progress_bar.set_postfix(成功=success_count, 失败=fail_count)
                print(f"\n添加 {torrent_file} 失败。响应: {response.text}")
            
            # 小延迟，避免API过载
            time.sleep(0.1)
            
        except Exception as e:
            fail_count += 1
            progress_bar.set_postfix(成功=success_count, 失败=fail_count)
            print(f"\n添加 {torrent_file} 时出错: {e}")
    
    return success_count, fail_count

def main():
    args = parse_arguments()
    
    # 验证torrent目录
    if not os.path.isdir(args.torrent_dir):
        print(f"错误: {args.torrent_dir} 不是有效目录")
        sys.exit(1)
    
    # 查找所有torrent文件及其相对路径和自动分类
    torrent_files_info = find_torrent_files(args.torrent_dir)
    if not torrent_files_info:
        print(f"在 {args.torrent_dir} 中未找到torrent文件")
        sys.exit(0)
    
    print(f"找到 {len(torrent_files_info)} 个torrent文件")
    
    # 显示自动分类信息（如果未指定用户分类）
    if not args.category and torrent_files_info:
        # 获取所有唯一的分类
        categories = set(info[2] for info in torrent_files_info)
        print(f"将使用以下自动生成的分类: {', '.join(categories)}")
    
    # 连接到qBittorrent API
    session = connect_to_qbittorrent(args.address)
    if not session:
        print("连接到qBittorrent API失败")
        sys.exit(1)
    
    # 添加torrents，每个都有各自的保存路径和分类
    success, failed = add_torrents(
        session, 
        args.address, 
        torrent_files_info, 
        args.save_to, 
        args.skip_hash_check, 
        args.category
    )
    
    print(f"\n摘要: 成功添加 {success} 个torrents，{failed} 个失败")

if __name__ == "__main__":
    main()