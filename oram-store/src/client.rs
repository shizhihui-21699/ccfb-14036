//! Path ORAM 客户端 —— 本系统的核心。
//!
//! 安全不变式：每一条病历块，要么在客户端 stash 里，要么在它当前叶子的
//! root→leaf 路径上。每次访问（读/写完全同构）：
//!   1. 查 position map 得旧叶子 x，为块随机抽一个新叶子 x'
//!   2. 【先落检查点】把 (remap 记录 + stash + pending=x) 加密写入云端 STATE
//!   3. 读 x 的整条路径，真实块并入 stash
//!   4. 沿路径贪心驱逐（每块尽量推向叶子方向），整条路径重新加密写回
//!   5. 【再落检查点】pending 清空
//!
//! 云端因此只能看到：读一条路径、写一条路径、两次定长状态写。
//! 读和写在外部行为上逐字节同构；stash/position map 永不出客户端，
//! 服务端观测不到任何与缓存内容相关的行为 —— 缓存不构成泄露面。
//!
//! 崩溃恢复：崩溃若发生在步骤 2 之前，操作从未发生；在 2 之后，
//! 恢复者读到 pending=x，用检查点里的 stash 重新执行 3-5（幂等），
//! 数据不丢不乱。

use crate::crypto::Cipher;
use crate::server::SimCloud;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

pub const DUMMY: u32 = u32::MAX;

/// 崩溃注入点（仅演示用）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CrashPoint {
    None,
    /// 写完检查点、还没读路径时断电
    AfterCheckpoint,
    /// 写回路径写了 k 个 bucket 后断电
    MidWriteback(usize),
}

/// 客户端状态检查点（加密前的明文结构）。
/// position map 的全量快照是云端独立对象，这里只存版本号 + 相对增量，
/// 任何客户端随时都能凭 (快照, 增量) 完整重建状态。
struct State {
    version: u64,
    snapshot_version: u64,           // 本状态基于哪个 position map 快照
    pending: i64,                    // -1 或正在写回的叶子
    pos_updates: Vec<(u32, u32)>,    // 自快照以来的 remap 增量 (block, leaf)
    stash: Vec<(u32, u32, Vec<u8>)>, // (block, leaf, data)
}

impl State {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.snapshot_version.to_le_bytes());
        out.extend_from_slice(&self.pending.to_le_bytes());
        out.extend_from_slice(&(self.pos_updates.len() as u32).to_le_bytes());
        for (b, l) in &self.pos_updates {
            out.extend_from_slice(&b.to_le_bytes());
            out.extend_from_slice(&l.to_le_bytes());
        }
        out.extend_from_slice(&(self.stash.len() as u32).to_le_bytes());
        for (b, l, d) in &self.stash {
            out.extend_from_slice(&b.to_le_bytes());
            out.extend_from_slice(&l.to_le_bytes());
            out.extend_from_slice(&(d.len() as u32).to_le_bytes());
            out.extend_from_slice(d);
        }
        out
    }

    fn decode(buf: &[u8]) -> Option<State> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            if p + n > buf.len() {
                return None;
            }
            let s = &buf[p..p + n];
            p += n;
            Some(s)
        };
        macro_rules! u32r {
            () => {
                u32::from_le_bytes(take(4)?.try_into().ok()?)
            };
        }
        macro_rules! u64r {
            () => {
                u64::from_le_bytes(take(8)?.try_into().ok()?)
            };
        }
        let version = u64r!();
        let snapshot_version = u64r!();
        let pending = i64::from_le_bytes(take(8)?.try_into().ok()?);
        let n_up = u32r!() as usize;
        let mut pos_updates = Vec::with_capacity(n_up);
        for _ in 0..n_up {
            pos_updates.push((u32r!(), u32r!()));
        }
        let n_stash = u32r!() as usize;
        let mut stash = Vec::with_capacity(n_stash);
        for _ in 0..n_stash {
            let b = u32r!();
            let l = u32r!();
            let n = u32r!() as usize;
            let d = take(n)?.to_vec();
            stash.push((b, l, d));
        }
        Some(State {
            version,
            snapshot_version,
            pending,
            pos_updates,
            stash,
        })
    }
}

/// 检查点加密后统一填充到 64KB 的倍数 —— 云端只能看到状态大小跨档，
/// 看不到 stash 的具体涨落（档位即隐蔽性与开销的平衡点）。
const STATE_PAD_GRANULE: usize = 64 * 1024;
/// 每积累这么多次 remap 就在检查点里附一次全量 position map 快照。
const SNAPSHOT_EVERY: usize = 128;

pub struct OramClient {
    pub id: u32,
    cipher: Cipher,
    pub levels: u32,
    pub leaves: u32,
    z: usize,
    block_data: usize, // 每块有效载荷字节数

    pos: Vec<u32>,                      // position map: block -> leaf
    stash: HashMap<u32, (u32, Vec<u8>)>, // block -> (leaf, data)
    pos_updates: Vec<(u32, u32)>,
    version: u64,
    snapshot_version: u64, // 当前 pos 对应的云端快照版本，0 = 无
    rng: StdRng,

    pub max_stash: usize,
    pub accesses: u64,
}

impl OramClient {
    pub fn new(id: u32, cipher: Cipher, capacity: u32, z: usize, block_data: usize, seed: u64) -> Self {
        let mut levels = 0u32;
        while (1u64 << levels) < capacity as u64 {
            levels += 1;
        }
        let leaves = 1u32 << levels;
        let mut rng = StdRng::seed_from_u64(seed);
        let pos: Vec<u32> = (0..capacity).map(|_| rng.gen_range(0..leaves)).collect();
        OramClient {
            id,
            cipher,
            levels,
            leaves,
            z,
            block_data,
            pos,
            stash: HashMap::new(),
            pos_updates: Vec::new(),
            version: 0,
            snapshot_version: 0,
            rng,
            max_stash: 0,
            accesses: 0,
        }
    }

    /// 线上加密块尺寸：nonce(12) + bid(4) + leaf(4) + data + tag(16)
    pub fn enc_block_bytes(&self) -> usize {
        12 + 8 + self.block_data + 16
    }

    // ---------- 检查点 ----------

    fn checkpoint(&mut self, cloud: &mut SimCloud, pending: i64) {
        self.version += 1;
        // 增量积累够了就把全量 position map 作为独立快照写出去
        if self.pos_updates.len() >= SNAPSHOT_EVERY {
            let mut plain = Vec::with_capacity(self.pos.len() * 4);
            for l in &self.pos {
                plain.extend_from_slice(&l.to_le_bytes());
            }
            let blob = self.cipher.encrypt(b"oram-snap", &plain);
            cloud.write_snapshot(self.id, self.version, blob);
            self.snapshot_version = self.version;
            self.pos_updates.clear();
        }
        let state = State {
            version: self.version,
            snapshot_version: self.snapshot_version,
            pending,
            pos_updates: self.pos_updates.clone(),
            stash: self
                .stash
                .iter()
                .map(|(b, (l, d))| (*b, *l, d.clone()))
                .collect(),
        };
        // 定长填充：先填明文再加密，云端看到的密文长度永远是 256KB 的倍数
        let mut plain = state.encode();
        const OVERHEAD: usize = 12 + 16; // nonce + tag
        let target = (plain.len() + OVERHEAD + STATE_PAD_GRANULE - 1) / STATE_PAD_GRANULE * STATE_PAD_GRANULE;
        plain.resize(target - OVERHEAD, 0);
        let blob = self.cipher.encrypt(b"oram-state", &plain);
        cloud
            .write_state(self.id, self.version, blob)
            .expect("state version conflict");
    }

    /// 从云端加载最新状态（含崩溃恢复）。每次拿到租约后调用。
    pub fn load_state(&mut self, cloud: &mut SimCloud) {
        let Some((version, blob)) = cloud.read_state(self.id) else {
            return; // 全新系统
        };
        let plain = self
            .cipher
            .decrypt(b"oram-state", &blob)
            .expect("state integrity check failed");
        let state = State::decode(&plain).expect("state decode failed");
        assert!(version == state.version, "state version mismatch");
        self.version = version;
        // 快照版本变了才重新下载全量 position map（通常只在客户端首次加入时）
        if state.snapshot_version != self.snapshot_version {
            let (sv, sblob) = cloud.read_snapshot(self.id).expect("state references missing snapshot");
            assert_eq!(sv, state.snapshot_version, "snapshot version mismatch");
            let splain = self
                .cipher
                .decrypt(b"oram-snap", &sblob)
                .expect("snapshot integrity check failed");
            assert_eq!(splain.len(), self.pos.len() * 4, "snapshot size mismatch");
            for (i, chunk) in splain.chunks_exact(4).enumerate() {
                self.pos[i] = u32::from_le_bytes(chunk.try_into().unwrap());
            }
            self.snapshot_version = sv;
        }
        for (b, l) in &state.pos_updates {
            self.pos[*b as usize] = *l;
        }
        self.pos_updates = state.pos_updates;
        self.stash = state
            .stash
            .into_iter()
            .map(|(b, l, d)| (b, (l, d)))
            .collect();

        // 崩溃恢复：有未完成的写回 → 幂等重放
        if state.pending >= 0 {
            let leaf = state.pending as u32;
            self.read_path_into_stash(cloud, leaf);
            self.writeback(cloud, leaf, CrashPoint::None);
            self.checkpoint(cloud, -1);
        }
    }

    // ---------- 路径操作 ----------

    fn read_path_into_stash(&mut self, cloud: &mut SimCloud, leaf: u32) {
        let buckets = cloud.read_path(self.id, leaf);
        for blob in buckets.into_iter().flatten() {
            for enc in blob.chunks_exact(self.enc_block_bytes()) {
                let Some(plain) = self.cipher.decrypt(b"oram-block", enc) else {
                    continue;
                };
                let bid = u32::from_le_bytes(plain[0..4].try_into().unwrap());
                if bid == DUMMY {
                    continue;
                }
                let bleaf = u32::from_le_bytes(plain[4..8].try_into().unwrap());
                // stash 优先：崩溃重放时 stash 里可能已有更新版本
                self.stash
                    .entry(bid)
                    .or_insert((bleaf, plain[8..].to_vec()));
            }
        }
    }

    /// 两叶子公共祖先的深度（root=0，leaf=levels）。
    fn deepest_level(&self, x: u32, y: u32) -> u32 {
        let xor = x ^ y;
        if xor == 0 {
            self.levels
        } else {
            self.levels - (31 - xor.leading_zeros()) - 1
        }
    }

    fn writeback(&mut self, cloud: &mut SimCloud, leaf: u32, crash: CrashPoint) {
        let nodes = cloud.path_nodes(leaf); // root→leaf
        // 每个 stash 块能放到的最深层级
        let mut deepest: Vec<(u32, u32)> = self
            .stash
            .iter()
            .map(|(b, (l, _))| (*b, self.deepest_level(leaf, *l)))
            .collect();
        // 自叶向根贪心放置
        let mut buckets: Vec<(u64, Vec<u8>)> = Vec::with_capacity(nodes.len());
        for (level, node) in nodes.iter().enumerate().rev() {
            let mut picked: Vec<u32> = Vec::new();
            for (b, d) in deepest.iter() {
                if *d >= level as u32 && picked.len() < self.z {
                    picked.push(*b);
                }
            }
            let picked_set: std::collections::HashSet<u32> = picked.iter().copied().collect();
            deepest.retain(|(b, _)| !picked_set.contains(b));
            let mut blob = Vec::with_capacity(self.z * self.enc_block_bytes());
            for b in &picked {
                let (l, d) = self.stash.remove(b).unwrap();
                let mut plain = Vec::with_capacity(8 + self.block_data);
                plain.extend_from_slice(&b.to_le_bytes());
                plain.extend_from_slice(&l.to_le_bytes());
                plain.extend_from_slice(&d);
                blob.extend_from_slice(&self.cipher.encrypt(b"oram-block", &plain));
            }
            // 填不满的位置补 dummy —— bucket 永远满员，云端看不到占用率
            for _ in picked.len()..self.z {
                let mut plain = Vec::with_capacity(8 + self.block_data);
                plain.extend_from_slice(&DUMMY.to_le_bytes());
                plain.extend_from_slice(&0u32.to_le_bytes());
                plain.extend_from_slice(&vec![0u8; self.block_data]);
                blob.extend_from_slice(&self.cipher.encrypt(b"oram-block", &plain));
            }
            buckets.push((*node, blob));
        }
        buckets.reverse(); // 恢复 root→leaf 顺序
        match crash {
            CrashPoint::MidWriteback(k) => {
                cloud.write_path_partial(self.id, leaf, buckets, k);
                // 模拟断电：函数直接返回，checkpoint(-1) 永远不会执行
            }
            _ => cloud.write_path(self.id, leaf, buckets),
        }
    }

    // ---------- 对外接口 ----------

    /// 统一访问入口：读（write=None）写（write=Some）外部行为完全一致。
    pub fn access(
        &mut self,
        cloud: &mut SimCloud,
        block: u32,
        write: Option<&[u8]>,
        crash: CrashPoint,
    ) -> Option<Vec<u8>> {
        self.accesses += 1;
        let old_leaf = self.pos[block as usize];
        let new_leaf = self.rng.gen_range(0..self.leaves);
        self.pos[block as usize] = new_leaf;
        self.pos_updates.push((block, new_leaf));

        // 写操作先把新数据放进 stash，再落检查点 —— 保证崩溃后新数据可恢复
        if let Some(data) = write {
            let mut d = data.to_vec();
            d.resize(self.block_data, 0);
            self.stash.insert(block, (new_leaf, d));
        }

        // 检查点：remap + stash + pending 一起原子落盘
        self.checkpoint(cloud, old_leaf as i64);
        if crash == CrashPoint::AfterCheckpoint {
            return None; // 模拟断电
        }

        self.read_path_into_stash(cloud, old_leaf);
        self.max_stash = self.max_stash.max(self.stash.len()); // 驱逐前 stash 占用

        let result = self.stash.get(&block).map(|(_, d)| d.clone());
        // 目标块 remap 后的叶子要更新（读操作也要 remap！）
        if let Some(entry) = self.stash.get_mut(&block) {
            entry.0 = new_leaf;
        }

        self.writeback(cloud, old_leaf, crash);
        if let CrashPoint::MidWriteback(_) = crash {
            return result; // 模拟断电：不写最终检查点
        }
        self.checkpoint(cloud, -1);
        result
    }
}
