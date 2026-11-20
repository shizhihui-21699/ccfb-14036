//! 攻击者视角分析：站在云端，只看访问日志，能推断出什么。

use crate::server::{AccessRecord, OpKind};
use std::collections::HashMap;

/// 朴素存储：日志直接给出热点记录 top-k。
pub fn naive_hotspots(log: &[AccessRecord], k: usize) -> Vec<(u64, usize, usize)> {
    let mut reads: HashMap<u64, usize> = HashMap::new();
    let mut writes: HashMap<u64, usize> = HashMap::new();
    for r in log {
        match r.op {
            OpKind::RawRead => *reads.entry(r.target).or_default() += 1,
            OpKind::RawWrite => *writes.entry(r.target).or_default() += 1,
            _ => {}
        }
    }
    let mut all: Vec<(u64, usize, usize)> = reads
        .iter()
        .map(|(id, r)| (*id, *r, *writes.get(id).unwrap_or(&0)))
        .collect();
    all.sort_by_key(|(_, r, w)| std::cmp::Reverse(r + w));
    all.truncate(k);
    all
}

/// ORAM：叶子访问频率的均匀性。把 2^L 个叶子合并成 bins 个桶做卡方检验。
/// 返回 (chi2/df, 最热的桶/期望)。两者都 ≈ 1 说明云端看到的接近纯随机。
pub fn leaf_uniformity(log: &[AccessRecord], leaves: u64, bins: usize) -> (f64, f64) {
    let mut counts = vec![0u64; bins];
    let mut total = 0u64;
    for r in log {
        if r.op == OpKind::ReadPath {
            let bin = (r.target * bins as u64 / leaves) as usize;
            counts[bin] += 1;
            total += 1;
        }
    }
    let expected = total as f64 / bins as f64;
    if expected == 0.0 {
        return (0.0, 0.0);
    }
    let chi2: f64 = counts
        .iter()
        .map(|c| (*c as f64 - expected).powi(2) / expected)
        .sum();
    let df = (bins - 1) as f64;
    let max_ratio = *counts.iter().max().unwrap() as f64 / expected;
    (chi2 / df, max_ratio)
}

/// ORAM：统计日志中每种操作的字节数分布 —— 验证读/写请求在外部无差别。
pub fn oram_op_profile(log: &[AccessRecord]) -> Vec<(OpKind, usize, usize)> {
    let mut m: HashMap<OpKind, (usize, usize)> = HashMap::new(); // (次数, 总字节)
    for r in log {
        let e = m.entry(r.op).or_default();
        e.0 += 1;
        e.1 += r.bytes;
    }
    let mut v: Vec<_> = m.into_iter().map(|(k, (n, b))| (k, n, b)).collect();
    v.sort_by_key(|(k, _, _)| format!("{:?}", k));
    v
}

/// 相邻两次路径访问撞同一叶子的次数 —— 期望约 total/2^L，验证顺序无规律。
pub fn adjacent_leaf_collisions(log: &[AccessRecord]) -> (usize, usize) {
    let leaves: Vec<u64> = log
        .iter()
        .filter(|r| r.op == OpKind::ReadPath)
        .map(|r| r.target)
        .collect();
    let collisions = leaves.windows(2).filter(|w| w[0] == w[1]).count();
    (collisions, leaves.len())
}

/// 均匀随机基线：同样多的访问打在同样多的叶子上，纯随机序列的统计量。
/// 用来对照 ORAM 的观测值 —— 两者接近说明云端看到的与抛硬币无异。
pub fn uniform_baseline(leaves: u64, bins: usize, n: usize, seed: u64) -> (f64, f64) {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(seed);
    let mut counts = vec![0u64; bins];
    for _ in 0..n {
        let leaf: u64 = rng.gen_range(0..leaves);
        counts[(leaf * bins as u64 / leaves) as usize] += 1;
    }
    let expected = n as f64 / bins as f64;
    let chi2: f64 = counts
        .iter()
        .map(|c| (*c as f64 - expected).powi(2) / expected)
        .sum();
    let max_ratio = *counts.iter().max().unwrap() as f64 / expected;
    (chi2 / (bins - 1) as f64, max_ratio)
}
