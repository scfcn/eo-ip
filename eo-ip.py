import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import os

def test_ip_port(ip, port=443, timeout=3):
    """测试单个IP的指定端口是否可达"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((str(ip), port))
        s.close()
        return result == 0
    except Exception as e:
        return False

def generate_ips_from_cidr(cidr):
    network = ipaddress.ip_network(cidr, strict=False)    
    ips = []
    # 包括网络地址(.0)
    ips.append(str(network.network_address))
    
    # 添加中间所有IP（从.1到.254）
    start_ip = int(network.network_address) + 1
    end_ip = int(network.broadcast_address) - 1
    
    for ip_int in range(start_ip, end_ip + 1):
        ips.append(str(ipaddress.IPv4Address(ip_int)))
    
    # 对于其他网络，排除广播地址(.255)
    return ips

def process_ips(ip_list, success_set, lock, max_workers=50):
    """处理IP列表并返回失败列表"""
    failed_ips = []
    success_count = 0
    fail_count = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(test_ip_port, ip): ip for ip in ip_list}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                success = future.result()
                if success:
                    with lock:
                        success_set.add(ip)
                        success_count += 1
                else:
                    failed_ips.append(ip)
                    fail_count += 1
            except Exception:
                failed_ips.append(ip)
                fail_count += 1
    
    print(f"Success: {success_count}, Failed: {fail_count}")
    return failed_ips

def natural_sort_key(ip):
    """生成IP地址的自然排序键"""
    return [int(part) for part in ip.split('.')]

def write_ips_to_file(ips, filename):
    """将IP列表排序后写入文件"""
    sorted_ips = sorted(ips, key=natural_sort_key)
    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")
    print(f"Saved {len(sorted_ips)} IPs to {filename}")

def main():
    input_file = "/ip_ranges.txt"   # 输入文件名
    success_file = "success_ips.txt"  # 成功IP输出文件
    failed_file = "failed_ips.txt"    # 失败IP输出文件
    max_retries = 1  # 最大重试次数
    max_workers = 100  # 最大并发线程数
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(success_file) or ".", exist_ok=True)
    
    # 读取并解析所有IP
    all_ips = []
    print(f"Reading IP ranges from {input_file}...")
    
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # 处理CIDR格式
                if '/' in line:
                    try:
                        ips = generate_ips_from_cidr(line)
                        all_ips.extend(ips)
                        print(f"Added {len(ips)} IPs from {line}")
                    except ValueError:
                        print(f"Invalid CIDR: {line}")
                # 处理单个IP
                else:
                    try:
                        ipaddress.ip_address(line)
                        all_ips.append(line)
                    except ValueError:
                        print(f"Invalid IP: {line}")
    
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    
    if not all_ips:
        print("No valid IP addresses found.")
        return
    
    # 对IP进行自然排序
    print("Sorting IP addresses...")
    all_ips.sort(key=natural_sort_key)
    print(f"Total IPs to test: {len(all_ips)}")
    
    # 使用集合存储成功IP（自动去重）
    success_ips = set()
    lock = threading.Lock()
    
    # 第一轮测试
    print("Starting first scan...")
    failed_ips = process_ips(all_ips, success_ips, lock, max_workers)
    print(f"First round completed. Failed IPs: {len(failed_ips)}")
    
    # 重试失败IP
    for retry in range(max_retries):
        if not failed_ips:
            break
            
        print(f"Retry round {retry+1} for {len(failed_ips)} IPs...")
        new_failed = process_ips(failed_ips, success_ips, lock, max_workers)
        failed_ips = new_failed
        time.sleep(1)  # 重试间隔
    
    # 将成功IP写入文件
    write_ips_to_file(success_ips, success_file)
    
    # 将失败IP写入文件
    write_ips_to_file(failed_ips, failed_file)
    
    # 统计信息
    success_count = len(success_ips)
    failed_count = len(failed_ips)
    total_count = len(all_ips)
    
    print(f"\nScan completed!")
    print(f"Total IPs scanned: {total_count}")
    print(f"Successful IPs: {success_count} ({success_count/total_count*100:.2f}%)")
    print(f"Failed IPs: {failed_count} ({failed_count/total_count*100:.2f}%)")
    print(f"Successful IPs saved to: {success_file}")
    print(f"Failed IPs saved to: {failed_file}")

if __name__ == "__main__":
    main()
