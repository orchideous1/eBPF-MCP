# NFS 探针目录速查

本文档供 `nfs-layer-observer` 技能在判断探针覆盖度时快速参考。

### 维护说明（重要）

本文档中的 **"已实现的探针"** 部分需要随项目探针集合的扩展而动态更新。

- 当 `nfs-layer-observer` 调用 `probe-creator` 新增 NFS/NFSD 探针后，**必须**重新读取 `probes/` 和 `ebpf/<layer>/` 目录，确认新探针已落地。
- 如果新探针确实已存在，**立即修改本文档**：将对应的函数条目从"未实现的探针"区域移到"已实现的探针"表格中，并补全探针名和采集字段。
- 快速确认命令：
  ```bash
  ls -1 probes/*.yaml | grep -E 'nfs-|nfsd4'
  ls -1 ebpf/NFS-client/
  ls -1 ebpf/nfsd/
  ```

---

## 1. nfs-client 层

### 1.1 已实现的探针

| 函数名 | 探针名 | 语义 | 采集字段 |
|--------|--------|------|---------|
| `nfs_file_read` | `nfs-file-read` | VFS 层文件读操作 | pid, comm, time_stamp, lat, size, file |
| `nfs_file_write` | `nfs-file-write` | VFS 层文件写操作 | pid, comm, time_stamp, lat, size, file |
| `nfs_getattr` | `nfs_getattr` | 获取文件属性 | pid, comm, time_stamp, lat |
| `nfs_setattr` | `nfs_setattr` | 设置文件属性 | pid, comm, time_stamp, lat |

### 1.2 未实现的探针（`layer: nfs_op`）

这部分函数覆盖面广、事件量大，属于 **L3（高/啰嗦）** 级别。

#### 高频通用操作（`common_high_freq`）

| 函数名 | 语义 | 推荐场景 |
|--------|------|---------|
| `nfs_lookup` | 目录项查找 | 路径解析慢、ls/cd 卡顿 |
| `nfs_read` | 通用读（非 VFS 入口） | 底层读路径分析 |
| `nfs_write` | 通用写（非 VFS 入口） | 底层写路径分析 |
| `nfs_create` | 创建文件 | 新建文件延迟高 |
| `nfs_rename` | 重命名 | mv 操作慢 |
| `nfs_unlink` | 删除文件 | rm 操作慢 |
| `nfs_mkdir` | 创建目录 | mkdir 操作慢 |
| `nfs_rmdir` | 删除目录 | rmdir 操作慢 |

#### 缓存/验证（`cache_revalidate`）

| 函数名 | 语义 | 推荐场景 |
|--------|------|---------|
| `nfs4_lookup_revalidate` | 查找结果缓存重验证 | dentry 缓存频繁失效 |
| `nfs_weak_revalidate` | 弱一致性重验证 | 缓存一致性敏感场景 |
| `nfs_dentry_delete` | 删除 dentry | 缓存回收异常 |
| `nfs_dentry_iput` | 释放 dentry 的 inode 引用 | inode 引用泄漏/积压 |
| `nfs_d_release` | 释放 dentry | 内存压力大时的 dentry 行为 |

#### 文件/锁/布局（`locking` / `layout_space` / `copy_move`）

| 函数名 | 语义 | 推荐场景 |
|--------|------|---------|
| `nfs_lock` | 文件锁（POSIX） | 文件锁竞争 |
| `nfs_flock` | flock 锁 | 批量锁操作慢 |
| `nfs42_fallocate` | 预分配空间（NFSv4.2） | 大文件 truncate/ fallocate 慢 |
| `nfs42_remap_file_range` | 重新映射文件范围 | reflink/去重场景 |
| `nfs4_copy_file_range` | 跨文件复制范围 | 服务端拷贝 offload |
| `nfs_atomic_open` | 原子打开（open+create） | 高并发文件创建 |
| `nfs_link` | 创建硬链接 | link 操作慢 |
| `nfs_symlink` | 创建符号链接 | symlink 操作慢 |
| `nfs_file_mmap` | 内存映射建立 | mmap 初始化慢 |
| `nfs4_file_open` | 打开文件（NFSv4） | open 延迟高 |
| `nfs4_file_flush` | 刷新写回缓冲区 | fsync/close 卡顿 |
| `nfs_file_release` | 释放文件引用 | close 路径异常 |
| `nfs_file_fsync` | 强制同步写回 | 同步写延迟高 |
| `nfs4_file_llseek` | 定位文件偏移 | seek 异常 |

#### xattr

| 函数名 | 语义 |
|--------|------|
| `nfs4_listxattr` | 列出扩展属性 |

#### 权限/其他

| 函数名 | 语义 |
|--------|------|
| `nfs_check_flags` | 检查文件打开标志 |
| `nfs4_setlease` | 设置租约（lease） |
| `nfs_mknod` | 创建设备节点 |
| `nfs_permission` | 权限检查（可能被注入延迟用于测试） |
| `nfs_d_automount` | 自动挂载处理（autofs） |

---

## 2. nfsd 层（`layer: nfsd_server`）

### 2.1 已实现的探针

| 函数名 | 探针名 | 语义 | 采集字段 |
|--------|--------|------|---------|
| `nfsd4_read` | `nfsd4_read` | 服务端 NFSv4 读 | pid, comm, time_stamp, lat, size, offset, xid |
| `nfsd4_write` | `nfsd4_write` | 服务端 NFSv4 写 | pid, comm, time_stamp, lat, size, offset, xid |
| `nfsd4_access` | `nfsd4_access` | 服务端 NFSv4 访问权限检查 | pid, comm, time_stamp, lat, xid |

### 2.2 未实现的探针

#### 高频核心操作（`common_high_freq`）

| 函数名 | 语义 | 推荐场景 |
|--------|------|---------|
| `nfsd4_getattr` | 获取属性 | getattr 风暴排查 |
| `nfsd4_setattr` | 设置属性 | 批量 setattr 慢 |
| `nfsd4_lookup` | 路径查找 | 服务端 lookup 瓶颈 |
| `nfsd4_readdir` | 读取目录 | ls 大目录慢 |

#### 会话管理（`session_mgmt`）

| 函数名 | 语义 | 推荐场景 |
|--------|------|---------|
| `nfsd4_create_session` | 创建会话 | 新客户端挂载慢、会话建立失败 |
| `nfsd4_destroy_session` | 销毁会话 | 客户端断开异常 |
| `nfsd4_sequence` | 序列控制 | NFSv4.1/4.2 序列号问题 |
| `nfsd4_bind_conn_to_session` | 绑定连接到会话 | 多连接 pNFS 场景 |
| `nfsd4_exchange_id` | 交换客户端/服务端 ID | 客户端首次接入慢 |
| `nfsd4_destroy_clientid` | 销毁客户端 ID | 客户端清理异常 |
| `nfsd4_reclaim_complete` | 回收完成通知 | 故障恢复后的状态确认 |

#### 锁状态管理（`lock_state`）

| 函数名 | 语义 |
|--------|------|
| `nfsd4_lock` | 加锁 |
| `nfsd4_lockt` | 测试锁 |
| `nfsd4_locku` | 解锁 |
| `nfsd4_release_lockowner` | 释放锁拥有者 |
| `nfsd4_test_stateid` | 测试 stateid |
| `nfsd4_free_stateid` | 释放 stateid |

#### pNFS 布局（`layout_pnfs`）

| 函数名 | 语义 | 推荐场景 |
|--------|------|---------|
| `nfsd4_getdeviceinfo` | 获取存储设备信息 | pNFS 设备发现慢 |
| `nfsd4_layoutget` | 获取布局 | 布局请求延迟高 |
| `nfsd4_layoutcommit` | 提交布局 | 布局更新慢 |
| `nfsd4_layoutreturn` | 归还布局 | 布局回收异常 |

#### 数据移动（`data_movement`）

| 函数名 | 语义 |
|--------|------|
| `nfsd4_copy` | 服务端拷贝 |
| `nfsd4_clone` | 服务端克隆 |
| `nfsd4_seek` | 定位 |
| `nfsd4_offload_status` | 查询卸载状态 |
| `nfsd4_offload_cancel` | 取消卸载 |
| `nfsd4_copy_notify` | 拷贝通知 |

#### 扩展属性（`xattr`）

| 函数名 | 语义 |
|--------|------|
| `nfsd4_getxattr` | 获取扩展属性 |
| `nfsd4_setxattr` | 设置扩展属性 |
| `nfsd4_listxattrs` | 列出扩展属性 |
| `nfsd4_removexattr` | 删除扩展属性 |

#### 其他文件操作

| 函数名 | 语义 |
|--------|------|
| `nfsd4_close` | 关闭文件 |
| `nfsd4_commit` | 提交已写数据（稳定化） |
| `nfsd4_create` | 创建文件/目录 |
| `nfsd4_delegreturn` | 归还委托 |
| `nfsd4_getfh` | 获取文件句柄 |
| `nfsd4_link` | 创建硬链接 |
| `nfsd4_lookupp` | 父目录查找 |
| `nfsd4_nverify` | 属性不等验证 |
| `nfsd4_open` | 打开文件 |
| `nfsd4_open_confirm` | 打开确认 |
| `nfsd4_open_downgrade` | 打开降级 |
| `nfsd4_putfh` | 设置当前文件句柄 |
| `nfsd4_putrootfh` | 切换根句柄 |
| `nfsd4_readlink` | 读取符号链接 |
| `nfsd4_remove` | 删除文件 |
| `nfsd4_rename` | 重命名 |
| `nfsd4_renew` | 续租 |
| `nfsd4_restorefh` | 恢复保存的句柄 |
| `nfsd4_savefh` | 保存当前句柄 |
| `nfsd4_secinfo` | 查询安全信息 |
| `nfsd4_setclientid` | 设置客户端 ID |
| `nfsd4_setclientid_confirm` | 确认客户端 ID |
| `nfsd4_verify` | 属性等验证 |
| `nfsd4_allocate` | 预分配空间 |
| `nfsd4_deallocate` | 释放空间 |
| `nfsd4_backchannel_ctl` | 后向通道控制 |
| `nfsd4_secinfo_no_name` | 无名安全信息查询 |
