# -*- coding: utf-8 -*-
"""
Ping 网络检测工具 - Windows GUI
功能：分组/地址两列管理、延迟ms、柱状图/饼图切换、多选测试、阈值设定、定时循环
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import subprocess
import threading
import json
import os
import re
import socket
import urllib.request
import urllib.error
import winsound
import queue
from datetime import datetime

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False

DATA_FILE = "data.json"


class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ping 网络检测工具")
        self.root.geometry("1100x750")
        self.root.minsize(950, 600)

        # ===== 数据模型 =====
        self.groups = {}           # {name: {"addrs": [...], "threshold": None}}
        self.global_threshold = None  # 全局延迟阈值(ms)
        self.chart_mode = "bar"    # bar / pie
        self.detect_mode = "icmp"  # icmp / tcp / http / all
        self.http_method = "HEAD"  # HEAD / GET
        self.http_keyword = ""     # 全局关键字（GET请求时校验响应内容）
        self.notify_mode = "off"   # off / fail / abnormal / both
        self.last_result = {"total": 0, "passed": 0, "failed": 0, "details": []}
        # details: [(address, group, latency_ms, status), ...]

        # 定时任务
        self.schedule_tasks = {}    # {task_id: {"target_type": "group"/"addr", "target": ..., "interval": min, "timer": ...}}
        self.global_schedule = None
        self.global_schedule_timer = None
        self.auto_clear_interval = None
        self.auto_clear_timer = None
        self._result_row = 0
        self._drag_data = None  # 拖拽数据: {"item": iid, "gname": str}
        self._addr_drag_data = None  # 地址拖拽数据
        self._current_group = None   # 当前选中的分组
        self._syncing_group = False   # 防止从地址反选分组时递归刷新
        self._stop_event = threading.Event()  # 强制停止检测的信号
        self._detect_button = None  # 停止检测按钮引用
        # 系统托盘
        self.tray_icon = None
        self.tray_queue = queue.Queue()
        self._last_tray_color = "gray"

        self.load_data()
        self._build_ui()
        self.refresh_all()
        # 默认选中"全部"分组
        self._current_group = "__ALL__"
        for child in self.group_tree.get_children():
            gv = self.group_tree.item(child, "values")
            if gv and gv[0] == "__ALL__":
                self.group_tree.selection_set(child)
                break
        self._bind_hotkeys()
        if TRAY_AVAILABLE:
            self._tray_setup()

    # ==================== 数据持久化 ====================
    def load_data(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.groups = data.get("groups", {})
                self.global_threshold = data.get("global_threshold", None)
                self.detect_mode = data.get("detect_mode", "tcp")
                self.http_method = data.get("http_method", "HEAD")
                self.http_keyword = data.get("http_keyword", "")
                self.notify_mode = data.get("notify_mode", "off")
                # 确保"未分组"始终存在
                if "未分组" not in self.groups:
                    self.groups["未分组"] = {"addrs": [], "threshold": None}
                # 兼容旧数据
                old_addrs = data.get("addresses", [])
                if not self.groups and old_addrs:
                    self.groups["未分组"] = {"addrs": [{"address": a["address"], "note": a.get("note", "")} for a in old_addrs], "threshold": None}
                # 兼容 groups 中直接存列表的旧格式
                for g in list(self.groups.keys()):
                    if isinstance(self.groups[g], list):
                        self.groups[g] = {"addrs": self.groups[g], "threshold": None}
                    elif isinstance(self.groups[g], dict) and "addrs" not in self.groups[g]:
                        addrs = []
                        for k, v in self.groups[g].items():
                            if isinstance(v, list):
                                addrs = v
                                break
                        self.groups[g] = {"addrs": addrs, "threshold": None}
            except Exception:
                self.groups = {"未分组": {"addrs": [], "threshold": None}}
        else:
            self.groups = {"未分组": {"addrs": [], "threshold": None}}

    def save_data(self):
        data = {"groups": self.groups, "global_threshold": self.global_threshold,
                "detect_mode": self.detect_mode, "notify_mode": self.notify_mode,
                "http_method": self.http_method, "http_keyword": self.http_keyword}
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"save err: {e}")

    def _all_addresses(self):
        result = []
        for gname, gdata in self.groups.items():
            for addr in gdata.get("addrs", []):
                addr["_group"] = gname
                result.append(addr)
        return result

    # ==================== 自动 DNS 解析 ====================
    def _resolve_domain(self, raw_name):
        """自动补全短名称为完整域名。不含点号的名称尝试 .com / www. 前缀"""
        raw = raw_name.strip()
        if not raw:
            return raw

        # 已经是IP地址，直接返回
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', raw):
            return raw
        # 已含点号，视为完整域名直接返回
        if '.' in raw:
            return raw

        # 短名称，尝试自动补全
        candidates = [f"{raw}.com", f"www.{raw}.com"]
        for candidate in candidates:
            try:
                socket.getaddrinfo(candidate, None, family=socket.AF_INET)
                return candidate
            except (socket.gaierror, OSError):
                continue
        # 都失败则返回原名（让用户看到DNS错误提示）
        return raw

    # ==================== TCP / HTTP 检测 ====================
    def _check_tcp(self, host, port, timeout=3):
        """TCP端口连通性检测，返回 (是否通, 延迟ms)"""
        try:
            start = datetime.now()
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return True, round(elapsed, 1)
        except (socket.timeout, socket.error, OSError):
            return False, None

    def _check_http(self, url_base, timeout=5, method="HEAD", keyword=""):
        """HTTP检测，返回 (HTTP状态码, 延迟ms, 关键字匹配结果)
        method: "HEAD" 或 "GET"
        keyword: 非空时在响应正文中查找该关键字
        关键字匹配结果: None=未启用, True=匹配成功, False=匹配失败
        """
        try:
            # 确保URL有scheme
            if not url_base.startswith("http"):
                url = f"http://{url_base}"
            else:
                url = url_base
            req = urllib.request.Request(url, method=method,
                                          headers={"User-Agent": "PingTool/2.0"})
            start = datetime.now()
            resp = urllib.request.urlopen(req, timeout=timeout)
            elapsed = (datetime.now() - start).total_seconds() * 1000
            # GET + 关键字匹配
            kw_result = None
            if method == "GET" and keyword:
                try:
                    body = resp.read().decode("utf-8", errors="replace")
                    kw_result = keyword in body
                except Exception:
                    kw_result = False
            return resp.status, round(elapsed, 1), kw_result
        except urllib.error.HTTPError as e:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return e.code, round(elapsed, 1), None
        except Exception:
            return None, None, None

    # ==================== 分组重命名 ====================
    def rename_group(self):
        sel = self.group_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择要重命名的分组")
            return
        gname = self.group_tree.item(sel[0], "values")[0]
        if gname in ("__ALL__",):
            messagebox.showwarning("提示", "不能重命名系统分组")
            return
        new_name = simpledialog.askstring("重命名分组", f"输入新名称 (原: {gname}):", initialvalue=gname)
        if new_name and new_name.strip() and new_name.strip() != gname:
            new_name = new_name.strip()
            if new_name in self.groups:
                messagebox.showwarning("提示", f"分组 {new_name} 已存在")
                return
            self.groups[new_name] = self.groups.pop(gname)
            # 更新地址中的分组引用
            self.refresh_all()
            self.save_data()

    def move_group_up(self):
        """将选中分组上移一位"""
        sel = self.group_tree.selection()
        if not sel:
            return
        gname = self.group_tree.item(sel[0], "values")[0]
        if gname in ("__ALL__",):
            return
        keys = list(self.groups.keys())
        idx = keys.index(gname)
        if idx <= 0:
            return
        keys[idx], keys[idx - 1] = keys[idx - 1], keys[idx]
        self.groups = {k: self.groups[k] for k in keys}
        self.refresh_all()
        self.save_data()

    def move_group_down(self):
        """将选中分组下移一位"""
        sel = self.group_tree.selection()
        if not sel:
            return
        gname = self.group_tree.item(sel[0], "values")[0]
        if gname in ("__ALL__",):
            return
        keys = list(self.groups.keys())
        idx = keys.index(gname)
        if idx >= len(keys) - 1:
            return
        keys[idx], keys[idx + 1] = keys[idx + 1], keys[idx]
        self.groups = {k: self.groups[k] for k in keys}
        self.refresh_all()
        self.save_data()

    # ==================== 分组拖拽排序 ====================
    def _on_drag_start(self, event):
        """记录拖拽起始项"""
        item = self.group_tree.identify_row(event.y)
        if not item:
            self._drag_data = None
            return
        gname = self.group_tree.item(item, "values")[0]
        # "全部"不可拖拽
        if gname == "__ALL__":
            self._drag_data = None
            return
        self._drag_data = {"item": item, "gname": gname}
        # 不移除选择，保留选择以便后续操作

    def _on_drag_motion(self, event):
        """拖拽过程中高亮目标行"""
        if not self._drag_data:
            return
        target = self.group_tree.identify_row(event.y)
        # 清除旧高亮
        for child in self.group_tree.get_children():
            tags = list(self.group_tree.item(child, "tags") or ())
            if self._drag_target_tag in tags:
                tags.remove(self._drag_target_tag)
                self.group_tree.item(child, tags=tags)
        # 新高亮（不能拖到"全部"上）
        if target and target != self._drag_data["item"]:
            tgname = self.group_tree.item(target, "values")[0]
            if tgname != "__ALL__":
                tags = list(self.group_tree.item(target, "tags") or ())
                if self._drag_target_tag not in tags:
                    tags.append(self._drag_target_tag)
                    self.group_tree.item(target, tags=tags)

    def _on_drag_release(self, event):
        """释放鼠标，执行重新排序"""
        try:
            # 清除所有高亮
            for child in self.group_tree.get_children():
                tags = list(self.group_tree.item(child, "tags") or ())
                if self._drag_target_tag in tags:
                    tags.remove(self._drag_target_tag)
                    self.group_tree.item(child, tags=tags)
        except Exception:
            pass

        if not self._drag_data:
            self._drag_data = None
            return

        target = self.group_tree.identify_row(event.y)
        if not target or target == self._drag_data["item"]:
            self._drag_data = None
            return

        tgname = self.group_tree.item(target, "values")[0]
        if tgname == "__ALL__":
            self._drag_data = None
            return

        src_gname = self._drag_data["gname"]
        keys = list(self.groups.keys())
        if src_gname not in keys or tgname not in keys:
            self._drag_data = None
            return

        src_idx = keys.index(src_gname)
        tgt_idx = keys.index(tgname)
        if src_idx == tgt_idx:
            self._drag_data = None
            return

        # 取出源，插入到目标位置
        keys.pop(src_idx)
        keys.insert(tgt_idx, src_gname)
        self.groups = {k: self.groups[k] for k in keys}
        self._drag_data = None
        self.refresh_all()
        self.save_data()

    # ==================== 地址拖拽排序 ====================
    def _on_addr_drag_press(self, event):
        """记录地址拖拽起始位置（延迟到移动5px后才激活拖拽）"""
        item = self.addr_tree.identify_row(event.y)
        if not item:
            self._addr_drag_data = None
            return
        gname = self._current_group
        if not gname:
            self._addr_drag_data = None
            return

        children = self.addr_tree.get_children()
        tree_idx = children.index(item)

        if gname == "__ALL__":
            # 从 display "   [groupname] address" 中解析所属分组
            display = self.addr_tree.item(item, "values")[0]
            m = re.match(r'^\s*\[(.+?)\]\s', display)
            if not m:
                self._addr_drag_data = None
                return
            src_group = m.group(1)
            if src_group not in self.groups:
                self._addr_drag_data = None
                return
            # 计算在该分组 addrs 列表中的索引（前面所有其他组的地址累加 + 分组内位置）
            inner_idx = 0
            for cg, cdata in self.groups.items():
                if cg == src_group:
                    break
                inner_idx += len(cdata.get("addrs", []))
            addr_idx = tree_idx - inner_idx
            if addr_idx < 0 or addr_idx >= len(self.groups[src_group].get("addrs", [])):
                self._addr_drag_data = None
                return
            self._addr_drag_data = {
                "item": item, "idx": addr_idx, "start_y": event.y, "active": False,
                "group": src_group, "is_all": True
            }
        else:
            if gname not in self.groups:
                self._addr_drag_data = None
                return
            if tree_idx < 0 or tree_idx >= len(self.groups[gname].get("addrs", [])):
                self._addr_drag_data = None
                return
            self._addr_drag_data = {
                "item": item, "idx": tree_idx, "start_y": event.y, "active": False,
                "group": gname, "is_all": False
            }

    def _on_addr_drag_motion(self, event):
        """地址拖拽移动，移动超过5px激活拖拽"""
        if not self._addr_drag_data:
            return
        if not self._addr_drag_data.get("active"):
            if abs(event.y - self._addr_drag_data["start_y"]) > 5:
                self._addr_drag_data["active"] = True
            else:
                return
        target = self.addr_tree.identify_row(event.y)
        if not target or target == self._addr_drag_data["item"]:
            return
        # 全部视图下，检查目标是否同组
        if self._addr_drag_data.get("is_all"):
            tg_display = self.addr_tree.item(target, "values")[0]
            from_dg = self._addr_drag_data["group"]
            m = re.match(r'^\s*\[(.+?)\]\s', tg_display)
            if not m or m.group(1) != from_dg:
                return  # 跨组不显示高亮
        # 高亮目标行
        for child in self.addr_tree.get_children():
            tags = list(self.addr_tree.item(child, "tags") or ())
            if "drag_target" in tags:
                tags.remove("drag_target")
                self.addr_tree.item(child, tags=tags)
        tg_tags = list(self.addr_tree.item(target, "tags") or ())
        if "drag_target" not in tg_tags:
            tg_tags.append("drag_target")
        self.addr_tree.item(target, tags=tg_tags)

    def _on_addr_drag_release(self, event):
        """释放鼠标，执行地址重新排序"""
        for child in self.addr_tree.get_children():
            tags = list(self.addr_tree.item(child, "tags") or ())
            if "drag_target" in tags:
                tags.remove("drag_target")
                self.addr_tree.item(child, tags=tags)

        if not self._addr_drag_data or not self._addr_drag_data.get("active"):
            self._addr_drag_data = None
            return

        target = self.addr_tree.identify_row(event.y)
        if not target or target == self._addr_drag_data["item"]:
            self._addr_drag_data = None
            return

        src_group = self._addr_drag_data["group"]
        src_idx = self._addr_drag_data["idx"]
        is_all = self._addr_drag_data.get("is_all", False)

        if src_group not in self.groups:
            self._addr_drag_data = None
            return

        addrs = self.groups[src_group].get("addrs", [])
        if src_idx >= len(addrs):
            self._addr_drag_data = None
            return

        if is_all:
            # 检查目标是否同组
            tg_display = self.addr_tree.item(target, "values")[0]
            m = re.match(r'^\s*\[(.+?)\]\s', tg_display)
            if not m or m.group(1) != src_group:
                self._addr_drag_data = None
                return  # 跨组不允许
            # 计算目标在组内的索引
            children = self.addr_tree.get_children()
            tgt_tree_idx = children.index(target)
            inner_offset = 0
            for cg, cdata in self.groups.items():
                if cg == src_group:
                    break
                inner_offset += len(cdata.get("addrs", []))
            tgt_idx = tgt_tree_idx - inner_offset
            if tgt_idx < 0 or tgt_idx >= len(addrs):
                self._addr_drag_data = None
                return
        else:
            children = self.addr_tree.get_children()
            try:
                tgt_idx = children.index(target)
            except ValueError:
                self._addr_drag_data = None
                return
            if tgt_idx >= len(addrs):
                self._addr_drag_data = None
                return

        addr_item = addrs.pop(src_idx)
        addrs.insert(tgt_idx, addr_item)
        self._addr_drag_data = None
        self.refresh_addr_list(self._current_group)
        self.save_data()

    # ==================== 配置导入导出 ====================
    def export_config(self):
        """导出全部配置到JSON文件"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            initialfile="ping_config_backup.json",
            title="导出配置"
        )
        if file_path:
            try:
                data = {"groups": self.groups, "global_threshold": self.global_threshold,
                        "detect_mode": self.detect_mode, "notify_mode": self.notify_mode,
                        "http_method": self.http_method, "http_keyword": self.http_keyword}
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                messagebox.showinfo("导出成功", f"配置已导出到:\n{file_path}")
            except Exception as e:
                messagebox.showerror("导出失败", str(e))

    def import_config(self):
        """从JSON文件导入配置（合并模式）"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            title="导入配置"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "groups" not in data and "addresses" not in data:
                    messagebox.showerror("导入失败", "文件格式不正确，缺少 groups 字段")
                    return
                imported_groups = data.get("groups", {})
                # 合并：同名分组合并地址
                for gname, gdata in imported_groups.items():
                    if isinstance(gdata, list):
                        gdata = {"addrs": gdata, "threshold": None}
                    if gname in self.groups:
                        exist_addrs = [a["address"] for a in self.groups[gname].get("addrs", [])]
                        for addr in gdata.get("addrs", []):
                            if addr["address"] not in exist_addrs:
                                self.groups[gname]["addrs"].append(addr)
                                exist_addrs.append(addr["address"])
                    else:
                        self.groups[gname] = gdata
                if data.get("global_threshold") is not None:
                    self.global_threshold = data["global_threshold"]
                if data.get("detect_mode"):
                    self.detect_mode = data["detect_mode"]
                if data.get("notify_mode"):
                    self.notify_mode = data["notify_mode"]
                if data.get("http_method"):
                    self.http_method = data["http_method"]
                if data.get("http_keyword"):
                    self.http_keyword = data["http_keyword"]
                self.refresh_all()
                self.save_data()
                messagebox.showinfo("导入成功", f"已导入配置，当前共 {sum(len(g.get('addrs',[])) for g in self.groups.values())} 个地址")
            except Exception as e:
                messagebox.showerror("导入失败", str(e))

    # ==================== 通知提醒 ====================
    def notify_setup(self):
        dialog = NotifyDialog(self.root, self.notify_mode, self.detect_mode, self.http_method, self.http_keyword)
        if dialog.result is not None:
            self.notify_mode = dialog.result["notify"]
            self.detect_mode = dialog.result["detect"]
            self.http_method = dialog.result["http_method"]
            self.http_keyword = dialog.result["http_keyword"]
            self._update_detect_label()
            self.save_data()

    def _update_detect_label(self):
        mode_map = {"icmp": "ICMP", "tcp": "ICMP+TCP", "all": "ICMP+TCP+HTTP"}
        label = f"检测: {mode_map.get(self.detect_mode, 'ICMP')}"
        if self.detect_mode == "all":
            label += f"({self.http_method})"
        self.detect_label.configure(text=label)

    def _trigger_notify(self, total, passed, failed, errors):
        """根据通知模式触发提醒（持续响铃直到关闭对话框）"""
        if self.notify_mode == "off":
            return
        abnormal = sum(1 for e in errors if "阈值" in e[2] or "异常" in e[2])
        has_fail = failed > 0
        has_abnormal = abnormal > 0
        should_notify = False
        if self.notify_mode == "fail" and has_fail:
            should_notify = True
        elif self.notify_mode == "abnormal" and has_abnormal:
            should_notify = True
        elif self.notify_mode == "both" and (has_fail or has_abnormal):
            should_notify = True

        if should_notify:
            msg = f"检测完成!\n总数: {total}  通过: {passed}  失败: {failed}"
            if has_fail:
                fail_info = "\n".join([f"[{e[1]}] {e[0]}: {e[2]}" for e in errors if "阈值" not in e[2] and "异常" not in e[2]])
                msg += f"\n\n失败:\n{fail_info}"
            if has_abnormal:
                abnormal_info = "\n".join([f"[{e[1]}] {e[0]}: {e[2]}" for e in errors if "阈值" in e[2] or "异常" in e[2]])
                msg += f"\n\n异常(超阈值):\n{abnormal_info}"

            # 后台线程循环响铃，直到对话框关闭
            bell_stop = threading.Event()
            def bell_loop():
                while not bell_stop.is_set():
                    winsound.Beep(800, 400)  # 800Hz, 400ms
            bell_thread = threading.Thread(target=bell_loop, daemon=True)
            bell_thread.start()

            # 直接调用模态对话框（阻塞主线程），关闭后停止响铃
            messagebox.showwarning("Ping 检测提醒", msg)
            bell_stop.set()
            bell_thread.join(timeout=2)

    # ==================== UI 构建 ====================
    def _build_ui(self):
        # 工具栏
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=(5, 0))

        row1 = ttk.Frame(toolbar)
        row1.pack(fill=tk.X, pady=2)
        row2 = ttk.Frame(toolbar)
        row2.pack(fill=tk.X, pady=(0, 3))

        ttk.Button(row1, text="添加地址", command=self.add_address).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="批量添加", command=self.batch_add).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="编辑", command=self.edit_address).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="删除", command=self.delete_selected).pack(side=tk.LEFT, padx=2)
        ttk.Separator(row1, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Button(row1, text="新建分组", command=self.add_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="重命名", command=self.rename_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="上移", command=self.move_group_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="下移", command=self.move_group_down).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="阈值设置", command=self.threshold_setup).pack(side=tk.LEFT, padx=2)

        ttk.Button(row2, text="▶ 检测选中", command=self.ping_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="▶ 检测全部", command=self.ping_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="停止循环", command=self.stop_schedule).pack(side=tk.LEFT, padx=2)
        self._detect_button = ttk.Button(row2, text="■ 停止检测", command=self.stop_detect, state=tk.DISABLED)
        self._detect_button.pack(side=tk.LEFT, padx=2)
        ttk.Separator(row2, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Button(row2, text="定时循环", command=self.schedule_setup).pack(side=tk.LEFT, padx=2)
        self.schedule_status = ttk.Label(row2, text="", foreground="gray")
        self.schedule_status.pack(side=tk.LEFT, padx=5)
        ttk.Separator(row2, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Button(row2, text="通知/检测设置", command=self.notify_setup).pack(side=tk.LEFT, padx=2)
        self.detect_label = ttk.Label(row2, text="检测: ICMP+TCP", foreground="blue")
        self.detect_label.pack(side=tk.LEFT, padx=5)
        ttk.Button(row2, text="导入", command=self.import_config).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="导出", command=self.export_config).pack(side=tk.LEFT, padx=2)

        # === 主体三列布局 ===
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # 左列：分组列表
        group_frame = ttk.LabelFrame(paned, text="分组列表")
        style = ttk.Style()
        style.configure("Group.Treeview", font=("Microsoft YaHei", 10), rowheight=28)
        style.configure("Group.Treeview.Heading", font=("Microsoft YaHei", 10, "bold"))
        self.group_tree = ttk.Treeview(group_frame, columns=(), show="tree", height=18,
                                        style="Group.Treeview")
        self.group_tree.heading("#0", text="  分组名称")
        self.group_tree.column("#0", width=170, minwidth=120)
        # 滚动条
        group_scroll = ttk.Scrollbar(group_frame, orient=tk.VERTICAL, command=self.group_tree.yview)
        self.group_tree.configure(yscrollcommand=group_scroll.set)
        self.group_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        group_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.group_tree.bind("<<TreeviewSelect>>", self.on_group_select)
        # 鼠标拖拽调整分组顺序
        self.group_tree.bind("<Button-1>", self._on_drag_start)
        self.group_tree.bind("<B1-Motion>", self._on_drag_motion)
        self.group_tree.bind("<ButtonRelease-1>", self._on_drag_release)
        self._drag_target_tag = "drag_target"  # 拖拽目标高亮
        self.group_tree.tag_configure(self._drag_target_tag, background="#cce5ff")
        # 交替行颜色
        self.group_tree.tag_configure("even", background="#f0f4f8")
        self.group_tree.tag_configure("all_tag", background="#e8f0fe", font=("Microsoft YaHei", 10, "bold"))

        # 中列：地址列表 (Treeview 替代 Listbox，视觉效果更好)
        addr_frame = ttk.LabelFrame(paned, text="地址列表")
        style.configure("Addr.Treeview", font=("Consolas", 10), rowheight=24)
        self.addr_tree = ttk.Treeview(addr_frame, columns=("display",), show="tree headings",
                                       selectmode=tk.EXTENDED, style="Addr.Treeview")
        self.addr_tree.heading("#0", text=" 序号")
        self.addr_tree.heading("display", text="地址 [阈值]")
        self.addr_tree.column("#0", width=50, anchor=tk.CENTER, stretch=False)
        self.addr_tree.column("display", width=200)
        addr_scroll = ttk.Scrollbar(addr_frame, orient=tk.VERTICAL, command=self.addr_tree.yview)
        self.addr_tree.configure(yscrollcommand=addr_scroll.set)
        self.addr_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        addr_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.addr_tree.bind("<Double-Button-1>", lambda e: self.edit_address())
        self.addr_tree.bind("<<TreeviewSelect>>", self._on_addr_select)
        # 地址拖拽排序
        self.addr_tree.bind("<ButtonPress-1>", self._on_addr_drag_press)
        self.addr_tree.bind("<B1-Motion>", self._on_addr_drag_motion)
        self.addr_tree.bind("<ButtonRelease-1>", self._on_addr_drag_release)
        # 地址行交替颜色
        self.addr_tree.tag_configure("addr_even", background="#f5f7fa")
        self.addr_tree.tag_configure("drag_target", background="#cce5ff")

        paned.add(group_frame, weight=1)
        paned.add(addr_frame, weight=2)

        # 右列：图表 + 结果 + 日志
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=4)

        # 图表切换按钮
        chart_toolbar = ttk.Frame(right_frame)
        chart_toolbar.pack(fill=tk.X)
        ttk.Label(chart_toolbar, text="图表类型:").pack(side=tk.LEFT)
        self.chart_var = tk.StringVar(value="bar")
        ttk.Radiobutton(chart_toolbar, text="柱状图", variable=self.chart_var, value="bar", command=lambda: self.draw_chart()).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(chart_toolbar, text="饼图", variable=self.chart_var, value="pie", command=lambda: self.draw_chart()).pack(side=tk.LEFT, padx=5)

        chart_frame = ttk.LabelFrame(right_frame, text="检测统计")
        chart_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 5))
        self.canvas = tk.Canvas(chart_frame, height=180, bg="#fafafa")
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.canvas.bind("<Configure>", lambda e: self.draw_chart())

        # 检测结果列表
        result_frame = ttk.LabelFrame(right_frame, text="检测结果 (地址 | 延迟ms | 状态)")
        result_frame.pack(fill=tk.BOTH, expand=False)

        # 筛选栏
        filter_bar = ttk.Frame(result_frame)
        filter_bar.pack(fill=tk.X, padx=2, pady=2)
        ttk.Label(filter_bar, text="筛选:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="全部")
        filter_combo = ttk.Combobox(filter_bar, textvariable=self.filter_var,
                                     values=["全部", "通过", "异常", "失败"], width=8, state="readonly")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        columns = ("address", "group", "latency", "status", "tcp", "http")
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=6)
        self.result_tree.heading("address", text="地址")
        self.result_tree.heading("group", text="分组")
        self.result_tree.heading("latency", text="延迟(ms)")
        self.result_tree.heading("status", text="状态")
        self.result_tree.heading("tcp", text="TCP")
        self.result_tree.heading("http", text="HTTP")
        self.result_tree.column("address", width=150)
        self.result_tree.column("group", width=65)
        self.result_tree.column("latency", width=65, anchor=tk.CENTER)
        self.result_tree.column("status", width=55, anchor=tk.CENTER)
        self.result_tree.column("tcp", width=50, anchor=tk.CENTER)
        self.result_tree.column("http", width=55, anchor=tk.CENTER)
        result_scroll = ttk.Scrollbar(result_frame, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=result_scroll.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        result_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # 异常日志
        log_frame = ttk.LabelFrame(right_frame, text="异常记录")
        log_frame.pack(fill=tk.BOTH, expand=True)
        log_toolbar = ttk.Frame(log_frame)
        log_toolbar.pack(fill=tk.X, padx=2, pady=2)
        ttk.Button(log_toolbar, text="导出日志", command=self.export_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(log_toolbar, text="清除日志", command=self.clear_errors).pack(side=tk.LEFT, padx=2)
        ttk.Button(log_toolbar, text="自动清除设置", command=self.auto_clear_setup).pack(side=tk.LEFT, padx=2)
        self.auto_clear_status = ttk.Label(log_toolbar, text="", foreground="gray")
        self.auto_clear_status.pack(side=tk.LEFT, padx=5)

        self.error_text = tk.Text(log_frame, height=8, state=tk.DISABLED, wrap=tk.WORD)
        err_scroll = ttk.Scrollbar(log_frame, command=self.error_text.yview)
        self.error_text.configure(yscrollcommand=err_scroll.set)
        self.error_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        err_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # 状态栏
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 3))
        self.status_label = ttk.Label(status_frame, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status_frame, mode="determinate", maximum=100)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ==================== 列表刷新 ====================
    def refresh_all(self):
        self.refresh_group_tree()
        self.refresh_addr_list()

    def refresh_group_tree(self):
        for item in self.group_tree.get_children():
            self.group_tree.delete(item)
        # "全部"虚拟分组
        total_count = sum(len(gdata.get("addrs", [])) for gdata in self.groups.values())
        self.group_tree.insert("", tk.END, text=f"  全部 ({total_count})",
                                values=("__ALL__",), tags=("all_tag",), open=True)
        for i, (gname, gdata) in enumerate(self.groups.items(), 1):
            th = gdata.get("threshold", None)
            cnt = len(gdata.get("addrs", []))
            label = f"  {gname} ({cnt})"
            if th is not None:
                label += f"  [{th}ms]"
            tag = "even" if i % 2 == 0 else ""
            self.group_tree.insert("", tk.END, text=label, values=(gname,), tags=(tag,))

    def refresh_addr_list(self, group_name=None):
        self.addr_tree.delete(*self.addr_tree.get_children())
        if group_name == "__ALL__":
            # 显示所有分组的所有地址
            idx = 1
            for gname, gdata in self.groups.items():
                for addr in gdata.get("addrs", []):
                    th = addr.get("threshold", None)
                    note = addr.get("note", "")
                    kw = addr.get("keyword", "")
                    display = addr["address"]
                    if th is not None:
                        display += f"  [{th}ms]"
                    if kw:
                        display += f" 🔍{kw}"
                    if note:
                        display += f" ({note})"
                    tag = "addr_even" if idx % 2 == 0 else ""
                    self.addr_tree.insert("", tk.END, text=str(idx),
                                           values=(f"[{gname}] {display}",), tags=(tag,))
                    idx += 1
        elif group_name and group_name in self.groups:
            for i, addr in enumerate(self.groups[group_name].get("addrs", []), 1):
                th = addr.get("threshold", None)
                note = addr.get("note", "")
                kw = addr.get("keyword", "")
                display = addr["address"]
                if th is not None:
                    display += f"  [{th}ms]"
                if kw:
                    display += f" 🔍{kw}"
                if note:
                    display += f" ({note})"
                tag = "addr_even" if i % 2 == 0 else ""
                self.addr_tree.insert("", tk.END, text=str(i),
                                       values=(display,), tags=(tag,))
        else:
            idx = 1
            for gname, gdata in self.groups.items():
                for addr in gdata.get("addrs", []):
                    th = addr.get("threshold", None)
                    note = addr.get("note", "")
                    kw = addr.get("keyword", "")
                    display = addr["address"]
                    if th is not None:
                        display += f"  [{th}ms]"
                    if kw:
                        display += f" 🔍{kw}"
                    if note:
                        display += f" ({note})"
                    self.addr_tree.insert("", tk.END, text=str(idx),
                                           values=(f"[{gname}] {display}",))
                    idx += 1

    def on_group_select(self, event):
        if self._syncing_group:
            return
        sel = self.group_tree.selection()
        if sel:
            item = sel[0]
            values = self.group_tree.item(item, "values")
            if values:
                gname = values[0]
                self._current_group = gname
                self.refresh_addr_list(gname)
            else:
                self._current_group = None
                self.refresh_addr_list(None)
        else:
            self.refresh_addr_list(None)

    def _on_addr_select(self, event):
        """地址被选中时 → 自动选中对应的分组（"全部"视图除外）"""
        sel = self.addr_tree.selection()
        if not sel or self._syncing_group:
            return
        # "全部"分组视图下不跳转
        if self._current_group == "__ALL__":
            return
        item = sel[0]
        values = self.addr_tree.item(item, "values")
        if not values:
            return
        display = values[0]
        # 从 display 中解析分组名: "[groupname] ..." 格式
        m = re.match(r'^\s*\[(.+?)\]\s', display)
        if m:
            target_group = m.group(1)
        else:
            # 没有前缀，说明是当前分组视图，使用 _current_group
            target_group = self._current_group
        if not target_group or target_group == "__ALL__":
            return
        # 检查当前分组是否已经相同
        current_sel = self.group_tree.selection()
        if current_sel:
            cv = self.group_tree.item(current_sel[0], "values")
            if cv and cv[0] == target_group:
                return  # 已经是目标分组，无需切换
        # 在分组树中找到对应项并选中
        for child in self.group_tree.get_children():
            gv = self.group_tree.item(child, "values")
            if gv and gv[0] == target_group:
                self._syncing_group = True
                try:
                    self.group_tree.selection_set(child)
                    self.group_tree.see(child)
                    self._current_group = target_group
                finally:
                    self._syncing_group = False
                break

    # ==================== 地址管理 ====================
    def get_current_group(self):
        sel = self.group_tree.selection()
        if sel:
            gname = self.group_tree.item(sel[0], "values")[0]
            if gname == "__ALL__":
                return list(self.groups.keys())[0] if self.groups else "未分组"
            return gname
        return list(self.groups.keys())[0] if self.groups else "未分组"

    def add_address(self):
        group = self.get_current_group()
        dialog = AddressDialog(self.root, "添加地址", groups=list(self.groups.keys()), default_group=group)
        if dialog.result:
            addr, grp, note, threshold, keyword = dialog.result
            # 自动DNS解析
            resolved = self._resolve_domain(addr)
            if grp not in self.groups:
                self.groups[grp] = {"addrs": [], "threshold": None}
            # 去重
            exist = [a["address"] for a in self.groups[grp].get("addrs", [])]
            if resolved in exist:
                messagebox.showwarning("提示", f"地址 {resolved} 在分组 {grp} 中已存在")
                return
            entry = {"address": resolved, "note": note, "original": addr}
            if threshold is not None:
                entry["threshold"] = threshold
            if keyword:
                entry["keyword"] = keyword
            # 提示解析结果
            if resolved != addr:
                messagebox.showinfo("DNS自动识别", f"'{addr}' → '{resolved}'")
            self.groups[grp]["addrs"].append(entry)
            self.refresh_all()
            self.save_data()

    def batch_add(self):
        group = self.get_current_group()
        dialog = BatchAddDialog(self.root, groups=list(self.groups.keys()), default_group=group)
        if dialog.result:
            addresses, grp = dialog.result
            if grp not in self.groups:
                self.groups[grp] = {"addrs": [], "threshold": None}
            exist = [a["address"] for a in self.groups[grp].get("addrs", [])]
            added = 0
            unresolved = []
            for a in addresses:
                a = a.strip()
                if not a:
                    continue
                resolved = self._resolve_domain(a)
                if resolved not in exist:
                    self.groups[grp]["addrs"].append({"address": resolved, "note": "", "original": a})
                    exist.append(resolved)
                    added += 1
                if resolved != a:
                    unresolved.append(f"'{a}' → '{resolved}'")
            self.refresh_all()
            self.save_data()
            msg = f"成功添加 {added} 个地址"
            if unresolved:
                msg += "\n\nDNS自动识别:\n" + "\n".join(unresolved)
            messagebox.showinfo("提示", msg)

    def edit_address(self, event=None):
        sel = self.addr_tree.selection()
        if not sel:
            return
        # Treeview selection → index
        children = self.addr_tree.get_children()
        idx = children.index(sel[0])

        # 确定当前是哪个分组
        sel_group = self.group_tree.selection()
        if sel_group:
            gname = self.group_tree.item(sel_group[0], "values")[0]
        else:
            return

        if gname == "__ALL__":
            # "全部"视图：从全局扁平列表获取
            all_flat = []
            for gn, gdata in self.groups.items():
                for addr in gdata.get("addrs", []):
                    all_flat.append((gn, addr))
            if idx < len(all_flat):
                grp, addr_info = all_flat[idx]
            else:
                return
        elif gname in self.groups:
            grp = gname
            if idx >= len(self.groups[grp]["addrs"]):
                return
            addr_info = self.groups[grp]["addrs"][idx]
        else:
            return

        dialog = AddressDialog(self.root, "编辑地址", groups=list(self.groups.keys()),
                               default_addr=addr_info["address"], default_group=grp,
                               default_note=addr_info.get("note", ""),
                               default_threshold=addr_info.get("threshold"),
                               default_keyword=addr_info.get("keyword", ""))
        if dialog.result:
            new_addr, new_grp, new_note, new_threshold, new_keyword = dialog.result
            # 从旧分组移除
            self.groups[grp]["addrs"].remove(addr_info)
            if not self.groups[grp]["addrs"]:
                if messagebox.askyesno("提示", f"分组 {grp} 已空，是否删除？"):
                    del self.groups[grp]
            # 添加到新分组
            if new_grp not in self.groups:
                self.groups[new_grp] = {"addrs": [], "threshold": None}
            new_entry = {"address": new_addr, "note": new_note}
            if new_threshold is not None:
                new_entry["threshold"] = new_threshold
            if new_keyword:
                new_entry["keyword"] = new_keyword
            self.groups[new_grp]["addrs"].append(new_entry)
            self.refresh_all()
            self.save_data()

    def delete_selected(self):
        sel_group = self.group_tree.selection()
        sel_addr = self.addr_tree.selection()

        if sel_addr:
            # 确定当前分组
            if sel_group:
                gname = self.group_tree.item(sel_group[0], "values")[0]
            else:
                return
            # Treeview selection → index
            idx = self.addr_tree.get_children().index(sel_addr[0])
            if gname == "__ALL__":
                all_flat = []
                for gn, gdata in self.groups.items():
                    for addr in gdata.get("addrs", []):
                        all_flat.append((gn, addr))
                if idx < len(all_flat):
                    grp, addr_info = all_flat[idx]
                    addr_name = addr_info["address"]
                    if messagebox.askyesno("确认", f"确定删除地址 {addr_name} 吗？"):
                        self.groups[grp]["addrs"].remove(addr_info)
                        if not self.groups[grp]["addrs"]:
                            del self.groups[grp]
            elif gname in self.groups:
                if idx < len(self.groups[gname]["addrs"]):
                    addr = self.groups[gname]["addrs"][idx]["address"]
                    if messagebox.askyesno("确认", f"确定删除地址 {addr} 吗？"):
                        del self.groups[gname]["addrs"][idx]
                        if not self.groups[gname]["addrs"]:
                            if messagebox.askyesno("提示", f"分组 {gname} 已空，是否同时删除该分组？"):
                                del self.groups[gname]
            self.refresh_all()
            self.save_data()
        elif sel_group:
            gname = self.group_tree.item(sel_group[0], "values")[0]
            if gname == "__ALL__" or gname == "未分组":
                return  # 不能删除虚拟分组和未分组
            if messagebox.askyesno("确认", f"确定删除分组 {gname} 及其所有地址吗？"):
                if gname in self.groups:
                    del self.groups[gname]
                self.refresh_all()
                self.save_data()

    def add_group(self):
        name = simpledialog.askstring("新建分组", "输入分组名称：")
        if name and name.strip():
            name = name.strip()
            if name in self.groups:
                messagebox.showwarning("提示", f"分组 {name} 已存在")
            else:
                self.groups[name] = {"addrs": [], "threshold": None}
                self.refresh_all()
                self.save_data()

    # ==================== 阈值设置 ====================
    def threshold_setup(self):
        dialog = ThresholdDialog(self.root, self.global_threshold, self.groups)
        if dialog.result is not None:
            self.global_threshold = dialog.result.get("global")
            for gname, th in dialog.result.get("groups", {}).items():
                if gname in self.groups:
                    self.groups[gname]["threshold"] = th
            self.refresh_group_tree()
            self.save_data()

    # ==================== Ping 检测 ====================
    def ping_selected(self):
        addrs = self._get_selected_addrs()
        if not addrs:
            messagebox.showwarning("提示", "请先选择要检测的地址（可用Ctrl多选）")
            return
        thread = threading.Thread(target=self._do_ping, args=(addrs,), daemon=True)
        thread.start()

    def ping_all(self):
        addrs = self._all_addresses()
        if not addrs:
            messagebox.showwarning("提示", "没有可检测的地址")
            return
        thread = threading.Thread(target=self._do_ping, args=(addrs,), daemon=True)
        thread.start()

    def _get_selected_addrs(self):
        result = []
        sel_items = self.addr_tree.selection()
        children = self.addr_tree.get_children()
        sel_indices = [children.index(item) for item in sel_items] if sel_items else []

        # 确定当前是哪个分组
        sel_group = self.group_tree.selection()
        if sel_group:
            gname = self.group_tree.item(sel_group[0], "values")[0]
        else:
            gname = None

        if gname == "__ALL__":
            # "全部"分组：从所有分组中按全局索引获取地址
            all_flat = []
            for gn, gdata in self.groups.items():
                for addr in gdata.get("addrs", []):
                    a = dict(addr)
                    a["_group"] = gn
                    all_flat.append(a)
            for idx in sel_indices:
                if idx < len(all_flat):
                    result.append(all_flat[idx])
        elif gname and gname in self.groups:
            for idx in sel_indices:
                if idx < len(self.groups[gname]["addrs"]):
                    addr = dict(self.groups[gname]["addrs"][idx])
                    addr["_group"] = gname
                    result.append(addr)
        else:
            return result

        # 如果选中了分组但没有选中地址，检测整个分组
        if not result and gname and gname != "__ALL__":
            if gname in self.groups:
                for addr in self.groups[gname]["addrs"]:
                    a = dict(addr)
                    a["_group"] = gname
                    result.append(a)
        elif not result and gname == "__ALL__":
            # 全部检测
            for gn, gdata in self.groups.items():
                for addr in gdata.get("addrs", []):
                    a = dict(addr)
                    a["_group"] = gn
                    result.append(a)
        return result

    def _parse_latency(self, output):
        """从 ping 输出中解析延迟 ms（兼容中英文 Windows）"""
        match = re.search(r"(?:time|时间)[=<](\d+)ms", output)
        if match:
            return int(match.group(1))
        match = re.search(r"(?:Average|平均)\s*=\s*(\d+)ms", output)
        if match:
            return int(match.group(1))
        return None

    def _get_threshold_for(self, group_name, addr_info=None):
        """获取地址的有效阈值：单地址阈值 > 分组阈值 > 全局阈值"""
        if addr_info and addr_info.get("threshold") is not None:
            return addr_info["threshold"]
        grp_th = self.groups.get(group_name, {}).get("threshold", None)
        if grp_th is not None:
            return grp_th
        return self.global_threshold

    def _do_ping(self, addrs):
        self._stop_event.clear()
        self.root.after(0, lambda: self._set_pinging(True))
        self.root.after(0, lambda: self._clear_results())

        total = len(addrs)
        passed = 0
        failed = 0
        errors = []
        details = []

        for idx, addr_info in enumerate(addrs):
            # 检查是否被强制停止
            if self._stop_event.is_set():
                self.root.after(0, lambda: self.status_label.configure(text="检测已停止"))
                break
            address = addr_info["address"]
            group_name = addr_info.get("_group", "未知")
            threshold = self._get_threshold_for(group_name, addr_info)

            self.root.after(0, lambda i=idx, t=total, a=address:
                            self.status_label.configure(text=f"检测中 ({i+1}/{t}): {a}"))
            self.root.after(0, lambda i=idx, t=total:
                            self.progress.configure(value=int((i+1)/t*100)))

            # 剥离路径部分用于主机检测
            host = address.split("/")[0] if "/" in address else address
            host = host.split(":")[0] if ":" in host else host

            # ---- ICMP Ping ----
            icmp_ok = False
            latency = None
            fail_reason = None
            try:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "2000", host],
                    capture_output=True, text=True, timeout=5,
                    encoding="gbk", errors="replace",
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                latency = self._parse_latency(result.stdout)
                icmp_ok = (result.returncode == 0 and
                           ("TTL=" in result.stdout or "time<" in result.stdout or
                            "time=" in result.stdout or "时间<" in result.stdout or
                            "时间=" in result.stdout))
                if not icmp_ok and result.returncode == 0 and "Approximate" in result.stdout:
                    icmp_ok = True
                if not icmp_ok:
                    stdout_lower = result.stdout.lower()
                    if "could not find host" in stdout_lower or "找不到" in result.stdout:
                        fail_reason = "DNS解析失败"
                    elif "超时" in result.stdout or "timed out" in stdout_lower:
                        fail_reason = "请求超时"
                    else:
                        fail_reason = "无法访问"
            except subprocess.TimeoutExpired:
                fail_reason = "Ping超时"
            except Exception as e:
                fail_reason = str(e)

            # ---- TCP 检测 ----
            tcp_ok = False
            tcp_latency = None
            if self.detect_mode in ("tcp", "all"):
                ok80, lat80 = self._check_tcp(host, 80)
                ok443, lat443 = self._check_tcp(host, 443)
                tcp_ok = ok80 or ok443
                tcp_latency = lat80 or lat443

            # ---- HTTP 检测 ----
            http_code = None
            http_latency = None
            http_kw_result = None
            http_kw = addr_info.get("keyword", "") or self.http_keyword
            if self.detect_mode == "all":
                code, lat, kw = self._check_http(host, method=self.http_method, keyword=http_kw)
                http_code = code
                http_latency = lat
                http_kw_result = kw

            # ---- 综合判断 ----
            overall_ok = icmp_ok
            if self.detect_mode in ("tcp", "all") and not icmp_ok and tcp_ok:
                overall_ok = True  # ICMP不通但TCP通也算可达
            if self.detect_mode == "all" and not overall_ok and http_code is not None:
                overall_ok = True  # ICMP/TCP不通但HTTP有响应也算可达

            tcp_str = f"通({tcp_latency:.0f}ms)" if tcp_ok else ("不通" if self.detect_mode in ("tcp", "all") else "-")
            # HTTP 结果显示
            if http_code:
                if http_kw_result is True:
                    http_str = f"{http_code} ✓"
                elif http_kw_result is False:
                    http_str = f"{http_code} ✗"
                else:
                    http_str = str(http_code)
            else:
                http_str = "-" if self.detect_mode != "all" else "不通"

            if overall_ok:
                # 检查关键字匹配失败
                if http_kw_result is False:
                    failed += 1
                    status = "内容不匹配"
                    errors.append((address, group_name, f"响应中未找到关键字'{http_kw}'"))
                    details.append((address, group_name, latency or http_latency, status))
                    self.root.after(0, lambda a=address, g=group_name, kw=http_kw:
                                   self._log_error(a, g, f"关键字'{kw}'不匹配"))
                    self.root.after(0, lambda a=address, g=group_name, l=latency, s=status:
                                   self._add_result(a, g, l, s, tcp_str, http_str))
                # 检查阈值
                elif latency is not None and threshold is not None and latency > threshold:
                    failed += 1
                    status = "异常"
                    errors.append((address, group_name, f"延迟 {latency}ms > 阈值 {threshold}ms"))
                    details.append((address, group_name, latency, status))
                    self.root.after(0, lambda a=address, g=group_name, l=latency, t=threshold:
                                   self._log_error(a, g, f"延迟 {l}ms > 阈值 {t}ms"))
                    self.root.after(0, lambda a=address, g=group_name, l=latency, s=status:
                                   self._add_result(a, g, l, s, tcp_str, http_str))
                else:
                    passed += 1
                    status = "通过"
                    if not icmp_ok and tcp_ok:
                        status = "通过(TCP)"
                    elif not icmp_ok and not tcp_ok and http_code is not None:
                        status = "通过(HTTP)"
                    elif http_kw_result is True:
                        status = "通过(内容匹配)"
                    # 优先ICMP延迟，其次TCP/HTTP延迟
                    display_latency = latency or tcp_latency or http_latency
                    details.append((address, group_name, display_latency, status))
                    self.root.after(0, lambda a=address, g=group_name, l=display_latency, s=status:
                                   self._add_result(a, g, l, s, tcp_str, http_str))
            else:
                failed += 1
                reason = fail_reason or "无法访问"
                errors.append((address, group_name, reason))
                details.append((address, group_name, None, "失败"))
                self.root.after(0, lambda a=address, g=group_name, r=reason:
                               self._log_error(a, g, r))
                self.root.after(0, lambda a=address, g=group_name:
                               self._add_result(a, g, None, "失败", tcp_str, http_str))

        self.last_result = {"total": total, "passed": passed, "failed": failed, "details": details}
        self.last_errors = errors

        self.root.after(0, lambda: self._set_pinging(False))
        self.root.after(0, lambda: self.status_label.configure(
            text=f"完成 - 总数:{total}  通过:{passed}  失败:{failed}"))
        self.root.after(0, self.draw_chart)
        # 更新托盘图标
        if failed == 0 and total > 0:
            tray_color, tray_tip = "green", f"Ping: {total}项 全部通过 ✓"
        elif failed == total and total > 0:
            tray_color, tray_tip = "red", f"Ping: {total}项 全部失败 ✗"
        elif failed > 0:
            tray_color, tray_tip = "yellow", f"Ping: {passed}通/{failed}败 ⚠"
        else:
            tray_color, tray_tip = "gray", "Ping 网络检测"
        self.root.after(0, lambda: self._update_tray(tray_color, tray_tip))
        self.root.after(100, lambda: self._trigger_notify(total, passed, failed, errors))

    def _add_result(self, address, group, latency, status, tcp="-", http="-"):
        lat_str = f"{latency}ms" if latency is not None else "-"
        if status == "通过":
            tag = "pass"
        elif status == "异常":
            tag = "warn"
        else:
            tag = "fail"
        self._result_row += 1
        tags = (tag,) if self._result_row % 2 == 1 else (tag, "odd")
        item = self.result_tree.insert("", tk.END, values=(address, group, lat_str, status, tcp, http), tags=tags)
        self.result_tree.see(item)
        self.result_tree.tag_configure("pass", foreground="green")
        self.result_tree.tag_configure("fail", foreground="red")
        self.result_tree.tag_configure("warn", foreground="orange")
        self.result_tree.tag_configure("odd", background="#f9f9f9")

    def _clear_results(self):
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        self._result_row = 0

    def _apply_filter(self):
        """根据筛选条件显示/隐藏结果行"""
        filter_val = self.filter_var.get()
        for item in self.result_tree.get_children():
            values = self.result_tree.item(item, "values")
            status = values[3] if len(values) > 3 else ""
            if filter_val == "全部":
                self.result_tree.reattach(item, "", tk.END)
            elif status == filter_val:
                self.result_tree.reattach(item, "", tk.END)
            else:
                self.result_tree.detach(item)

    def _set_pinging(self, pinging):
        if pinging:
            self.progress.pack(fill=tk.X, padx=2, pady=2)
            self.progress.configure(value=0)
            self._detect_button.configure(state=tk.NORMAL)
        else:
            self.progress.pack_forget()
            self._detect_button.configure(state=tk.DISABLED)

    def stop_detect(self):
        """强制停止所有正在进行的检测"""
        self._stop_event.set()
        self.status_label.configure(text="正在停止检测...")

    # ==================== 图表 ====================
    def draw_chart(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 50 or h < 50:
            return

        total = self.last_result.get("total", 0)
        passed = self.last_result.get("passed", 0)
        failed = self.last_result.get("failed", 0)

        if total == 0:
            self.canvas.create_text(w // 2, h // 2, text="暂无检测数据", fill="gray", font=("", 14))
            return

        mode = self.chart_var.get()
        if mode == "pie":
            self._draw_pie_chart(w, h, total, passed, failed)
        else:
            self._draw_bar_chart(w, h, total, passed, failed)

    def _draw_bar_chart(self, w, h, total, passed, failed):
        bar_count = 3
        bar_width = min(80, (w - 100) // bar_count)
        spacing = (w - bar_width * bar_count) // (bar_count + 1)
        baseline = h - 40
        max_val = max(total, 1)
        scale = (baseline - 60) / max_val

        colors = ["#4CAF50", "#2196F3", "#F44336"]
        labels = ["检测总数", "通过", "失败"]
        values = [total, passed, failed]

        for i in range(bar_count):
            x1 = spacing + i * (bar_width + spacing)
            x2 = x1 + bar_width
            y1 = baseline - values[i] * scale
            y2 = baseline
            self.canvas.create_rectangle(x1, y1, x2, y2, fill=colors[i], outline="", width=0)
            self.canvas.create_text((x1 + x2) // 2, y1 - 15, text=str(values[i]),
                                     fill=colors[i], font=("Arial", 14, "bold"))
            self.canvas.create_text((x1 + x2) // 2, baseline + 18, text=labels[i],
                                     fill="#333", font=("", 10))
        self.canvas.create_text(w // 2, 15, text="最近一次检测结果",
                                 fill="#333", font=("", 12, "bold"))

    def _draw_pie_chart(self, w, h, total, passed, failed):
        cx, cy = w // 2, h // 2
        r = min(cx, cy) - 20
        if r < 30:
            return

        pass_angle = 360 * passed / total if total > 0 else 0
        fail_angle = 360 * failed / total if total > 0 else 0

        if pass_angle >= 360:
            self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                     fill="#2196F3", outline="white", width=2)
        elif pass_angle > 0:
            self.canvas.create_arc(cx - r, cy - r, cx + r, cy + r,
                                    start=0, extent=pass_angle, fill="#2196F3", outline="white", width=2)
        if fail_angle >= 360:
            self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                     fill="#F44336", outline="white", width=2)
        elif fail_angle > 0:
            self.canvas.create_arc(cx - r, cy - r, cx + r, cy + r,
                                    start=pass_angle, extent=fail_angle, fill="#F44336", outline="white", width=2)

        lx = 15
        self.canvas.create_rectangle(lx, 15, lx + 14, 29, fill="#2196F3", outline="")
        self.canvas.create_text(lx + 50, 22, text=f"通过: {passed}", anchor=tk.W, fill="#333", font=("", 10))
        self.canvas.create_rectangle(lx, 35, lx + 14, 49, fill="#F44336", outline="")
        self.canvas.create_text(lx + 50, 42, text=f"失败: {failed}", anchor=tk.W, fill="#333", font=("", 10))
        self.canvas.create_text(w // 2, 15, text="最近一次检测结果",
                                 fill="#333", font=("", 12, "bold"))

    # ==================== 异常日志 ====================
    def _log_error(self, address, group, reason):
        self.error_text.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.error_text.insert(tk.END, f"[{timestamp}] [{group}] {address} - {reason}\n")
        self.error_text.see(tk.END)
        self.error_text.configure(state=tk.DISABLED)

    def clear_errors(self):
        self.error_text.configure(state=tk.NORMAL)
        self.error_text.delete("1.0", tk.END)
        self.error_text.configure(state=tk.DISABLED)

    def export_logs(self):
        """导出日志到文本文件，支持筛选 — 一步完成"""
        raw_text = self.error_text.get("1.0", tk.END).strip()
        if not raw_text:
            messagebox.showwarning("提示", "日志为空，无需导出")
            return

        dialog = ExportLogDialog(self.root)
        if dialog.result is None:
            return  # 用户取消

        filter_mode = dialog.result["filter"]
        file_path = dialog.result["path"]
        if not file_path:
            return

        lines = raw_text.split("\n")
        filtered = []
        for line in lines:
            if filter_mode == "全部":
                filtered.append(line)
            elif filter_mode == "失败":
                if "DNS解析失败" in line or "请求超时" in line or "无法访问" in line:
                    filtered.append(line)
            elif filter_mode == "异常":
                if "阈值" in line or "异常" in line:
                    filtered.append(line)
            elif filter_mode == "成功":
                if "通过" in line and "阈值" not in line:
                    filtered.append(line)

        if not filtered:
            messagebox.showwarning("提示", "没有符合筛选条件的日志")
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"Ping 检测日志 - 导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"筛选条件: {filter_mode}\n")
                f.write(f"共 {len(filtered)} 条记录\n")
                f.write("=" * 50 + "\n\n")
                f.write("\n".join(filtered))
            messagebox.showinfo("导出成功", f"已导出 {len(filtered)} 条记录到:\n{file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ==================== 定时循环任务 ====================
    def schedule_setup(self):
        target_type = None
        target = None
        sel_group = self.group_tree.selection()
        sel_addr = self.addr_tree.selection()
        if sel_addr:
            target_type = "addr"
            group = self.get_current_group()
            idx = self.addr_tree.get_children().index(sel_addr[0])
            if idx < len(self.groups[group]["addrs"]):
                target = self.groups[group]["addrs"][idx]["address"]
        elif sel_group:
            target_type = "group"
            target = self.group_tree.item(sel_group[0], "values")[0]

        dialog = ScheduleDialog(self.root, target_type, target, self.schedule_tasks)
        if dialog.result:
            action, task_data = dialog.result
            if action == "add":
                tid = f"{task_data['target_type']}_{task_data['target']}"
                if tid in self.schedule_tasks:
                    self.schedule_tasks[tid]["timer"].cancel()
                self.schedule_tasks[tid] = task_data
                self._start_single_schedule(tid)
                self._update_schedule_status()
            elif action == "remove":
                tid = task_data
                if tid in self.schedule_tasks:
                    self.schedule_tasks[tid]["timer"].cancel()
                    del self.schedule_tasks[tid]
                self._update_schedule_status()
            elif action == "clear_all":
                for tid in list(self.schedule_tasks.keys()):
                    self.schedule_tasks[tid]["timer"].cancel()
                self.schedule_tasks.clear()
                self._update_schedule_status()

    def _start_single_schedule(self, tid):
        task = self.schedule_tasks[tid]

        def run():
            if tid not in self.schedule_tasks:
                return
            t = self.schedule_tasks[tid]
            if t["target_type"] == "addr":
                addrs = []
                for gname, gdata in self.groups.items():
                    for a in gdata.get("addrs", []):
                        if a["address"] == t["target"]:
                            addr_info = dict(a)
                            addr_info["_group"] = gname
                            addrs.append(addr_info)
                            break
                if addrs:
                    threading.Thread(target=self._do_ping, args=(addrs,), daemon=True).start()
            elif t["target_type"] == "group":
                if t["target"] in self.groups:
                    addrs = []
                    for a in self.groups[t["target"]]["addrs"]:
                        addr = dict(a)
                        addr["_group"] = t["target"]
                        addrs.append(addr)
                    if addrs:
                        threading.Thread(target=self._do_ping, args=(addrs,), daemon=True).start()
            timer = threading.Timer(t["interval"] * 60, run)
            timer.daemon = True
            timer.start()
            if tid in self.schedule_tasks:
                self.schedule_tasks[tid]["timer"] = timer

        timer = threading.Timer(task["interval"] * 60, run)
        timer.daemon = True
        timer.start()
        self.schedule_tasks[tid]["timer"] = timer

    def stop_schedule(self):
        """停止所有定时循环任务"""
        for tid in list(self.schedule_tasks.keys()):
            self.schedule_tasks[tid]["timer"].cancel()
        self.schedule_tasks.clear()
        self._update_schedule_status()

    def _update_schedule_status(self):
        if self.schedule_tasks:
            text = "定时: " + ", ".join([f"{t['target']}({t['interval']}min)" for t in self.schedule_tasks.values()])
            self.schedule_status.configure(text=text[:80], foreground="green")
        else:
            self.schedule_status.configure(text="", foreground="gray")

    # ==================== 自动清除日志 ====================
    def auto_clear_setup(self):
        dialog = AutoClearDialog(self.root, current_interval=self.auto_clear_interval)
        if dialog.result is not None:
            self.auto_clear_interval = dialog.result
            if self.auto_clear_interval and self.auto_clear_interval > 0:
                self.auto_clear_status.configure(
                    text=f"自动清除: 每 {self.auto_clear_interval} 分钟", foreground="blue")
                self._start_auto_clear()
            else:
                self.auto_clear_status.configure(text="", foreground="gray")
                self._stop_auto_clear()

    def _start_auto_clear(self):
        self._stop_auto_clear()

        def do_clear():
            self.clear_errors()
            if self.auto_clear_interval and self.auto_clear_interval > 0:
                self.auto_clear_timer = threading.Timer(self.auto_clear_interval * 60, do_clear)
                self.auto_clear_timer.daemon = True
                self.auto_clear_timer.start()

        self.auto_clear_timer = threading.Timer(self.auto_clear_interval * 60, do_clear)
        self.auto_clear_timer.daemon = True
        self.auto_clear_timer.start()

    def _stop_auto_clear(self):
        if self.auto_clear_timer:
            self.auto_clear_timer.cancel()
            self.auto_clear_timer = None

    def on_close(self):
        """窗口关闭 → 最小化到托盘，退出托盘才真正退出"""
        if TRAY_AVAILABLE and self.tray_icon:
            self.root.withdraw()
        else:
            self._do_quit()

    def _do_quit(self):
        for tid in list(self.schedule_tasks.keys()):
            self.schedule_tasks[tid]["timer"].cancel()
        self.schedule_tasks.clear()
        self._stop_auto_clear()
        self.save_data()
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.destroy()

    # ── 系统托盘 ──
    def _tray_setup(self):
        """初始化系统托盘"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.protocol("WM_DESTROY", self._do_quit)
        tray_thread = threading.Thread(target=self._tray_run, daemon=True)
        tray_thread.start()
        self._poll_tray_queue()

    def _create_tray_image(self, color):
        """创建64x64纯色圆图标"""
        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        margin = 4
        draw.ellipse([margin, margin, size - margin, size - margin], fill=color)
        return img

    def _show_window(self, icon=None):
        """从托盘恢复窗口"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_run(self):
        """托盘线程主循环"""
        colors = {"green": (0, 180, 0), "yellow": (220, 180, 0), "red": (200, 40, 40), "gray": (150, 150, 150)}
        color = colors.get(self._last_tray_color, colors["gray"])
        image = self._create_tray_image(color)
        menu = pystray.Menu(
            pystray.MenuItem("显示主窗口", self._show_window, default=True),
            pystray.MenuItem("检测全部", lambda: self.tray_queue.put("ping_all")),
            pystray.MenuItem("退出", self._tray_quit),
        )
        self.tray_icon = pystray.Icon("ping_monitor", image, "Ping 网络检测", menu)
        self.tray_icon.run()

    def _tray_quit(self, icon=None):
        """托盘退出 → 彻底关闭"""
        self.root.after(0, self._do_quit)

    def _update_tray(self, color, tooltip):
        """更新托盘图标颜色和悬停提示"""
        if not TRAY_AVAILABLE or not self.tray_icon:
            return
        colors = {"green": (0, 180, 0), "yellow": (220, 180, 0), "red": (200, 40, 40), "gray": (150, 150, 150)}
        self._last_tray_color = color
        try:
            self.tray_icon.icon = self._create_tray_image(colors.get(color, colors["gray"]))
            self.tray_icon.title = tooltip[:64]
        except Exception:
            pass

    def _poll_tray_queue(self):
        """轮询托盘菜单命令"""
        try:
            cmd = self.tray_queue.get_nowait()
            if cmd == "ping_all":
                self.root.after(0, self.ping_all)
        except queue.Empty:
            pass
        self.root.after(500, self._poll_tray_queue)

    # ── 快捷键 ──
    def _bind_hotkeys(self):
        """绑定全局快捷键"""
        self.root.bind("<F5>", lambda e: self._hotkey_ping())
        self.root.bind("<Control-a>", lambda e: self._hotkey_select_all())
        self.root.bind("<Control-A>", lambda e: self._hotkey_select_all())
        self.root.bind("<Delete>", lambda e: self._hotkey_delete())

    def _hotkey_ping(self):
        """F5: 选中则检选中的，否则检全部"""
        if self.addr_tree.selection():
            self.ping_selected()
        else:
            self.ping_all()

    def _hotkey_select_all(self):
        """Ctrl+A: 全选地址"""
        all_items = self.addr_tree.get_children()
        if all_items:
            self.addr_tree.selection_set(all_items)

    def _hotkey_delete(self):
        """Delete: 删除选中"""
        self.delete_selected()


# ==================== 对话框 ====================
class AddressDialog(tk.Toplevel):
    def __init__(self, parent, title, groups, default_addr="", default_group="", default_note="", default_threshold=None, default_keyword=""):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.geometry("400x310")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        ttk.Label(self, text="地址:").grid(row=0, column=0, padx=10, pady=(15, 5), sticky=tk.W)
        self.addr_entry = ttk.Entry(self, width=40)
        self.addr_entry.grid(row=0, column=1, padx=10, pady=(15, 5))
        self.addr_entry.insert(0, default_addr)

        ttk.Label(self, text="分组:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.group_var = tk.StringVar()
        self.group_combo = ttk.Combobox(self, textvariable=self.group_var, values=groups, width=37)
        self.group_combo.grid(row=1, column=1, padx=10, pady=5)
        if default_group:
            self.group_var.set(default_group)
        elif groups:
            self.group_var.set(groups[0])

        ttk.Label(self, text="备注:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.note_entry = ttk.Entry(self, width=40)
        self.note_entry.grid(row=2, column=1, padx=10, pady=5)
        self.note_entry.insert(0, default_note)

        ttk.Label(self, text="阈值(ms):").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        self.threshold_entry = ttk.Entry(self, width=15)
        self.threshold_entry.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W)
        if default_threshold is not None:
            self.threshold_entry.insert(0, str(default_threshold))
        ttk.Label(self, text="留空使用分组/全局阈值", foreground="gray").grid(row=3, column=1, padx=(120, 0), pady=5, sticky=tk.W)

        ttk.Label(self, text="关键字:").grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        self.keyword_entry = ttk.Entry(self, width=40)
        self.keyword_entry.grid(row=4, column=1, padx=10, pady=5)
        self.keyword_entry.insert(0, default_keyword)
        ttk.Label(self, text="GET请求校验响应内容关键字", foreground="gray", font=("", 8)).grid(row=4, column=1, padx=(0, 0), pady=(25, 0), sticky=tk.W)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=15)
        ttk.Button(btn_frame, text="确定", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)
        self.addr_entry.focus_set()
        self.wait_window()

    def on_ok(self):
        addr = self.addr_entry.get().strip()
        group = self.group_var.get().strip()
        note = self.note_entry.get().strip()
        keyword = self.keyword_entry.get().strip()
        threshold = None
        th_val = self.threshold_entry.get().strip()
        if th_val:
            try:
                threshold = int(th_val)
                if threshold <= 0:
                    threshold = None
            except ValueError:
                messagebox.showwarning("提示", "阈值请输入有效数字")
                return
        if not addr:
            messagebox.showwarning("提示", "请输入地址")
            return
        if not group:
            messagebox.showwarning("提示", "请选择或输入分组")
            return
        self.result = (addr, group, note, threshold, keyword)
        self.destroy()


class BatchAddDialog(tk.Toplevel):
    def __init__(self, parent, groups=None, default_group=""):
        super().__init__(parent)
        self.title("批量添加地址")
        self.result = None
        self.geometry("500x400")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        ttk.Label(self, text="每行一个地址，支持域名或IP:").pack(anchor=tk.W, padx=10, pady=(10, 5))
        self.text = tk.Text(self, height=15, width=60)
        self.text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        frame = ttk.Frame(self)
        frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(frame, text="目标分组:").pack(side=tk.LEFT)
        self.group_var = tk.StringVar(value=default_group or "未分组")
        self.group_entry = ttk.Entry(frame, textvariable=self.group_var, width=30)
        self.group_entry.pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="确定添加", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)
        self.wait_window()

    def on_ok(self):
        text = self.text.get("1.0", tk.END).strip()
        group = self.group_var.get().strip()
        if not text:
            messagebox.showwarning("提示", "请输入地址")
            return
        if not group:
            messagebox.showwarning("提示", "请输入分组名称")
            return
        addresses = [line.strip() for line in text.split("\n") if line.strip()]
        self.result = (addresses, group)
        self.destroy()


class ThresholdDialog(tk.Toplevel):
    def __init__(self, parent, global_threshold, groups):
        super().__init__(parent)
        self.title("阈值设置")
        self.result = None
        self.geometry("480x400")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        ttk.Label(self, text="全局延迟阈值 (ms)，留空表示不限制：", font=("", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.global_var = tk.StringVar(value=str(global_threshold) if global_threshold else "")
        ttk.Entry(self, textvariable=self.global_var, width=20).pack(anchor=tk.W, padx=10)

        ttk.Label(self, text="分组阈值 (优先级高于全局阈值)：", font=("", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(15, 5))

        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10)

        canvas = tk.Canvas(list_frame, height=180)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=canvas.yview)
        self.group_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=self.group_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)

        self.group_thresholds = {}
        for gname, gdata in groups.items():
            frame = ttk.Frame(self.group_frame)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=gname, width=18).pack(side=tk.LEFT)
            var = tk.StringVar(value=str(gdata.get("threshold", "")) if gdata.get("threshold") is not None else "")
            ttk.Entry(frame, textvariable=var, width=12).pack(side=tk.LEFT, padx=5)
            ttk.Label(frame, text="ms").pack(side=tk.LEFT)
            self.group_thresholds[gname] = var

        self.group_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="确定", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)
        self.wait_window()

    def on_ok(self):
        result = {"global": None, "groups": {}}
        gval = self.global_var.get().strip()
        if gval:
            try:
                result["global"] = int(gval)
                if result["global"] <= 0:
                    result["global"] = None
            except ValueError:
                messagebox.showwarning("提示", "全局阈值请输入有效数字")
                return
        for gname, var in self.group_thresholds.items():
            val = var.get().strip()
            if val:
                try:
                    result["groups"][gname] = int(val)
                    if result["groups"][gname] <= 0:
                        result["groups"][gname] = None
                except ValueError:
                    messagebox.showwarning("提示", f"分组 {gname} 阈值请输入有效数字")
                    return
        self.result = result
        self.destroy()


class ScheduleDialog(tk.Toplevel):
    def __init__(self, parent, target_type, target, existing_tasks):
        super().__init__(parent)
        self.title("定时循环设置")
        self.result = None
        self.geometry("500x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        if existing_tasks:
            ttk.Label(self, text="已有定时任务：", font=("", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 5))
            list_frame = ttk.Frame(self)
            list_frame.pack(fill=tk.X, padx=10)
            self.task_listbox = tk.Listbox(list_frame, height=5)
            self.task_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self.task_ids = []
            for tid, t in existing_tasks.items():
                label = f"{t['target_type']}: {t['target']} - 每 {t['interval']} 分钟"
                self.task_listbox.insert(tk.END, label)
                self.task_ids.append(tid)
            btn_frame = ttk.Frame(list_frame)
            btn_frame.pack(side=tk.RIGHT, padx=5)
            ttk.Button(btn_frame, text="删除选中", command=self.remove_task).pack(pady=2)
            ttk.Button(btn_frame, text="全部清除", command=self.clear_all).pack(pady=2)

        ttk.Label(self, text="新增定时任务：", font=("", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 5))

        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.X, padx=10)
        if target_type and target:
            ttk.Label(info_frame, text=f"目标: {target_type} - {target}").pack(side=tk.LEFT)
        else:
            ttk.Label(info_frame, text="目标: 请在左侧选择分组或地址后打开此设置").pack(side=tk.LEFT)

        interval_frame = ttk.Frame(self)
        interval_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(interval_frame, text="间隔(分钟):").pack(side=tk.LEFT)
        self.interval_var = tk.StringVar(value="5")
        ttk.Entry(interval_frame, textvariable=self.interval_var, width=10).pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="添加定时任务", command=self.add_task).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="关闭", command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.target_type = target_type
        self.target = target
        self.wait_window()

    def remove_task(self):
        sel = self.task_listbox.curselection()
        if sel:
            idx = sel[0]
            if idx < len(self.task_ids):
                self.result = ("remove", self.task_ids[idx])
                self.destroy()

    def clear_all(self):
        self.result = ("clear_all", None)
        self.destroy()

    def add_task(self):
        if not self.target_type or not self.target:
            messagebox.showwarning("提示", "请先在主界面选择分组或地址")
            return
        try:
            interval = int(self.interval_var.get().strip())
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("提示", "请输入有效的正整数值")
            return
        self.result = ("add", {"target_type": self.target_type, "target": self.target, "interval": interval})
        self.destroy()


class ExportLogDialog(tk.Toplevel):
    """日志导出 — 筛选 + 选择路径一步完成"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("导出日志")
        self.result = None
        self.geometry("380x280")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        ttk.Label(self, text="选择导出范围：", font=("", 10, "bold")).pack(pady=(15, 10))

        self.filter_var = tk.StringVar(value="全部")
        options = [
            ("全部日志", "全部"),
            ("仅失败 (DNS/超时/无法访问)", "失败"),
            ("仅异常 (超阈值)", "异常"),
            ("仅成功通过", "成功"),
        ]
        for text, value in options:
            ttk.Radiobutton(self, text=text, variable=self.filter_var, value=value).pack(anchor=tk.W, padx=40, pady=3)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(self, text="保存路径：", font=("", 10, "bold")).pack(anchor=tk.W, padx=20)
        path_frame = ttk.Frame(self)
        path_frame.pack(fill=tk.X, padx=20, pady=5)
        self.path_var = tk.StringVar(value=f"ping_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        ttk.Entry(path_frame, textvariable=self.path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(path_frame, text="浏览", command=self._browse).pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="导出", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)
        self.wait_window()

    def _browse(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile=self.path_var.get(),
            title="选择保存路径"
        )
        if path:
            self.path_var.set(path)

    def on_ok(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请选择保存路径")
            return
        self.result = {"filter": self.filter_var.get(), "path": path}
        self.destroy()


class NotifyDialog(tk.Toplevel):
    """通知提醒 + 检测模式设置"""
    def __init__(self, parent, current_notify, current_detect, http_method="HEAD", http_keyword=""):
        super().__init__(parent)
        self.title("通知与检测设置")
        self.result = None
        self.geometry("400x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="通知提醒设置", font=("", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))

        self.notify_var = tk.StringVar(value=current_notify)
        notify_options = [
            ("关闭", "off"),
            ("仅失败时提醒", "fail"),
            ("仅异常时提醒 (超阈值)", "abnormal"),
            ("失败+异常都提醒", "both"),
        ]
        for text, value in notify_options:
            ttk.Radiobutton(main, text=text, variable=self.notify_var, value=value).pack(anchor=tk.W, padx=20, pady=2)

        ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

        ttk.Label(main, text="检测模式设置", font=("", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))

        self.detect_var = tk.StringVar(value=current_detect)
        detect_options = [
            ("仅 ICMP Ping", "icmp"),
            ("ICMP + TCP 端口检测 (80/443)", "tcp"),
            ("全部: ICMP + TCP + HTTP", "all"),
        ]
        for text, value in detect_options:
            ttk.Radiobutton(main, text=text, variable=self.detect_var, value=value).pack(anchor=tk.W, padx=20, pady=2)

        # HTTP 方式
        http_frame = ttk.Frame(main)
        http_frame.pack(fill=tk.X, padx=20, pady=(5, 0))
        ttk.Label(http_frame, text="HTTP方法:").pack(side=tk.LEFT)
        self.http_var = tk.StringVar(value=http_method)
        ttk.Radiobutton(http_frame, text="HEAD", variable=self.http_var, value="HEAD").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(http_frame, text="GET", variable=self.http_var, value="GET").pack(side=tk.LEFT, padx=5)

        kw_frame = ttk.Frame(main)
        kw_frame.pack(fill=tk.X, padx=20, pady=(5, 0))
        ttk.Label(kw_frame, text="关键字(可选):").pack(side=tk.LEFT)
        self.kw_var = tk.StringVar(value=http_keyword)
        ttk.Entry(kw_frame, textvariable=self.kw_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Label(main, text="GET时校验响应中是否包含此关键字", foreground="gray", font=("", 8)).pack(padx=20, anchor=tk.W)

        ttk.Label(main, text="⚠ 检测模式越高，耗时越长", foreground="gray", font=("", 8)).pack(pady=(5, 5))

        btn_frame = ttk.Frame(main)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="确定", command=self.on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=10)
        self.wait_window()

    def on_ok(self):
        self.result = {"notify": self.notify_var.get(), "detect": self.detect_var.get(),
                       "http_method": self.http_var.get(), "http_keyword": self.kw_var.get().strip()}
        self.destroy()


class AutoClearDialog(tk.Toplevel):
    def __init__(self, parent, current_interval=None):
        super().__init__(parent)
        self.title("自动清除日志设置")
        self.result = None
        self.geometry("350x160")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        ttk.Label(self, text="设置自动清除日志间隔（分钟）：").pack(padx=10, pady=(15, 5))
        self.interval_var = tk.StringVar(value=str(current_interval) if current_interval else "")
        entry = ttk.Entry(self, textvariable=self.interval_var, width=15)
        entry.pack(pady=5)
        ttk.Label(self, text="设为 0 或留空则停止自动清除", foreground="gray").pack()
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="确定", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)
        entry.focus_set()
        self.wait_window()

    def on_ok(self):
        try:
            val = self.interval_var.get().strip()
            if val == "":
                self.result = None
            else:
                self.result = int(val)
                if self.result < 0:
                    self.result = None
        except ValueError:
            messagebox.showwarning("提示", "请输入有效的数字")
            return
        self.destroy()


# ═══════════════════════════════════════════════════════════
#  程序入口
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()