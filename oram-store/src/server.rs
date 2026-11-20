//! 模拟云端：一个"诚实但好奇"的对象存储。
//! 它忠实地存取数据，但会记录每一次访问的完整日志（操作类型、路径、字节数、时间），
//! 演示的最后我们就拿这份日志来做攻击者视角的分析。
//!
//! 云端能看到什么，完全由我们调用它的方式决定：
//!   - read_path / write_path  只暴露"哪条叶子路径"，不暴露块身份
//!   - read_state / write_state 客户端检查点（加密 blob，定长填充）
//!   - raw_read / raw_write    对照组：朴素加密存储，直接暴露记录号

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    ReadPath,   // ORAM: 读一条 root→leaf 路径
    WritePath,  // ORAM: 写回一条路径
    ReadState,  // 读取客户端状态检查点
    WriteState, // 写客户端状态检查点
    RawRead,    // 对照组：朴素读
    RawWrite,   // 对照组：朴素写
}

#[derive(Clone, Debug)]
pub struct AccessRecord {
    pub seq: u64,
    pub client: u32,
    pub op: OpKind,
    /// ReadPath/WritePath 时为叶子编号；Raw* 时为记录号。
    pub target: u64,
    pub bytes: usize,
}

pub struct SimCloud {
    pub levels: u32, // 树高 L，叶子数 = 2^L
    pub z: usize,    // 每个 bucket 的块数
    pub block_bytes: usize, // 单个加密块的线上字节数（含 nonce/tag）

    /// 稀疏物化的 bucket 存储：node_id -> 加密 blob。
    /// 真实云端这里是一棵完整的树（N=1M 时约 2M 个 bucket）；
    /// 模拟中未写过的 bucket 视为"加密空 bucket"，读取时按全尺寸计带宽。
    buckets: HashMap<u64, Vec<u8>>,
    /// 客户端状态检查点（单槽，版本化原子写）。
    state: Option<(u64, Vec<u8>)>, // (version, blob)
    /// position map 全量快照（独立对象，检查点按版本号引用它）。
    snapshot: Option<(u64, Vec<u8>)>,
    /// 对照组用的朴素记录存储。
    raw: HashMap<u64, Vec<u8>>,
    /// 租约：(持有者, 获取时间)。带 TTL，持有者崩溃后自动过期。
    lease: Option<(u32, Instant)>,
    lease_ttl: Duration,

    pub log: Vec<AccessRecord>,
    pub bytes_read: u64,
    pub bytes_written: u64,
    seq: u64,
}

impl SimCloud {
    pub fn new(levels: u32, z: usize, block_bytes: usize) -> Self {
        SimCloud {
            levels,
            z,
            block_bytes,
            buckets: HashMap::new(),
            state: None,
            snapshot: None,
            raw: HashMap::new(),
            lease: None,
            lease_ttl: Duration::from_millis(500),
            log: Vec::new(),
            bytes_read: 0,
            bytes_written: 0,
            seq: 0,
        }
    }

    fn record(&mut self, client: u32, op: OpKind, target: u64, bytes: usize) {
        self.seq += 1;
        self.log.push(AccessRecord {
            seq: self.seq,
            client,
            op,
            target,
            bytes,
        });
    }

    /// 路径上的节点编号（root→leaf）。叶子 leaf 对应节点 (2^L - 1 + leaf)。
    pub fn path_nodes(&self, leaf: u32) -> Vec<u64> {
        let mut nodes = Vec::with_capacity(self.levels as usize + 1);
        let mut node = (1u64 << self.levels) - 1 + leaf as u64;
        loop {
            nodes.push(node);
            if node == 0 {
                break;
            }
            node = (node - 1) / 2;
        }
        nodes.reverse(); // root 在前
        nodes
    }

    /// ORAM 读路径：返回 root→leaf 顺序的 bucket blob（未物化的为 None）。
    /// 带宽按完整路径计费 —— 真实云端每个 bucket 都有加密内容。
    pub fn read_path(&mut self, client: u32, leaf: u32) -> Vec<Option<Vec<u8>>> {
        let nodes = self.path_nodes(leaf);
        let path_bytes = nodes.len() * self.z * self.block_bytes;
        self.bytes_read += path_bytes as u64;
        self.record(client, OpKind::ReadPath, leaf as u64, path_bytes);
        nodes
            .iter()
            .map(|n| self.buckets.get(n).cloned())
            .collect()
    }

    /// ORAM 写回路径：buckets 为 root→leaf 顺序的加密 blob（定长）。
    pub fn write_path(&mut self, client: u32, leaf: u32, buckets: Vec<(u64, Vec<u8>)>) {
        let path_bytes = buckets.len() * self.z * self.block_bytes;
        self.bytes_written += path_bytes as u64;
        self.record(client, OpKind::WritePath, leaf as u64, path_bytes);
        for (node, blob) in buckets {
            self.buckets.insert(node, blob);
        }
    }

    /// 崩溃注入演示用：只写回路径的前 k 个 bucket 就"断电"。
    pub fn write_path_partial(&mut self, client: u32, leaf: u32, buckets: Vec<(u64, Vec<u8>)>, k: usize) {
        let n = buckets.len().min(k);
        let path_bytes = n * self.z * self.block_bytes;
        self.bytes_written += path_bytes as u64;
        self.record(client, OpKind::WritePath, leaf as u64, path_bytes);
        for (node, blob) in buckets.into_iter().take(n) {
            self.buckets.insert(node, blob);
        }
    }

    // ---- 客户端状态检查点（加密 blob，云端只见定长数据）----

    pub fn read_state(&mut self, client: u32) -> Option<(u64, Vec<u8>)> {
        let bytes = self.state.as_ref().map(|(_, b)| b.len()).unwrap_or(0);
        self.bytes_read += bytes as u64;
        self.record(client, OpKind::ReadState, 0, bytes);
        self.state.clone()
    }

    /// 原子写检查点：版本必须单调递增，否则拒绝（防止并发写撕裂）。
    pub fn write_state(&mut self, client: u32, version: u64, blob: Vec<u8>) -> Result<(), &'static str> {
        if let Some((v, _)) = &self.state {
            if version <= *v {
                return Err("stale state version");
            }
        }
        self.bytes_written += blob.len() as u64;
        self.record(client, OpKind::WriteState, 0, blob.len());
        self.state = Some((version, blob));
        Ok(())
    }

    // ---- position map 快照（target=1 以区别于检查点）----

    pub fn read_snapshot(&mut self, client: u32) -> Option<(u64, Vec<u8>)> {
        let bytes = self.snapshot.as_ref().map(|(_, b)| b.len()).unwrap_or(0);
        self.bytes_read += bytes as u64;
        self.record(client, OpKind::ReadState, 1, bytes);
        self.snapshot.clone()
    }

    pub fn write_snapshot(&mut self, client: u32, version: u64, blob: Vec<u8>) {
        self.bytes_written += blob.len() as u64;
        self.record(client, OpKind::WriteState, 1, blob.len());
        self.snapshot = Some((version, blob));
    }

    // ---- 租约：多客户端互斥。持有者崩溃 → TTL 过期后他人接管 ----

    pub fn acquire_lease(&mut self, client: u32) -> bool {
        if let Some((owner, since)) = self.lease {
            if owner == client {
                return true;
            }
            if since.elapsed() < self.lease_ttl {
                return false;
            }
            // 原持有者疑似崩溃，租约过期，允许接管
        }
        self.lease = Some((client, Instant::now()));
        true
    }

    pub fn release_lease(&mut self, client: u32) {
        if let Some((owner, _)) = self.lease {
            if owner == client {
                self.lease = None;
            }
        }
    }

    // ---- 对照组：朴素加密存储（内容加密，但访问模式裸奔）----

    pub fn raw_read(&mut self, client: u32, record: u64, bytes: usize) -> Option<Vec<u8>> {
        self.bytes_read += bytes as u64;
        self.record(client, OpKind::RawRead, record, bytes);
        self.raw.get(&record).cloned()
    }

    pub fn raw_write(&mut self, client: u32, record: u64, blob: Vec<u8>) {
        self.bytes_written += blob.len() as u64;
        self.record(client, OpKind::RawWrite, record, blob.len());
        self.raw.insert(record, blob);
    }
}
