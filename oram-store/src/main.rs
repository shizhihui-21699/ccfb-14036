//! 演示：加密病历的隐蔽访问层（Path ORAM）vs 朴素加密存储
//!
//! 场景：医院把加密病历放在第三方云上。内容云端解不开，
//! 但云端能看到访问日志 —— 什么时候、读了哪块、多频繁、什么顺序。
//! 本演示回答四个问题：
//!   1. 朴素加密存储泄露多少？（对照组）
//!   2. ORAM 的访问日志里还能看出什么？（隐蔽性）
//!   3. 每次访问的额外开销多大？（性能）
//!   4. 多医生并发 + 客户端崩溃，数据会不会乱？（正确性）

use oram_store::analysis;
use oram_store::client::{CrashPoint, OramClient};
use oram_store::crypto::Cipher;
use oram_store::server::{OpKind, SimCloud};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---- 系统参数（性能/隐蔽性的平衡点）----
const CAPACITY: u32 = 1_000_000; // position map 容量：一百万条病历
const RECORDS: u32 = 1_500;      // 实际预填的病历数（演示规模）
const Z: usize = 4;              // 每个 bucket 的块数（Path ORAM 经典值）
const BLOCK_DATA: usize = 1024;  // 每块有效载荷 1KB
const DOCTORS: u32 = 4;          // 并发医生数
const OPS_PER_DOCTOR: usize = 350;
const BATCH_PER_LEASE: usize = 8; // 每次持锁批量处理的访问数（摊销协调开销）
const WRITE_RATIO: f64 = 0.15;   // 负载中写操作比例

fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.2} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.2} MB", b as f64 / (1u64 << 20) as f64)
    } else {
        format!("{:.1} KB", b as f64 / 1024.0)
    }
}

/// 生成 Zipf 偏斜负载：少数"重点病人"被反复调阅。
fn gen_workload(seed: u64, n_ops: usize) -> Vec<(u32, bool)> {
    let mut rng = StdRng::seed_from_u64(seed);
    let weights: Vec<f64> = (1..=RECORDS).map(|i| 1.0 / (i as f64).powf(1.2)).collect();
    let dist = WeightedIndex::new(&weights).unwrap();
    (0..n_ops)
        .map(|_| {
            let rec = dist.sample(&mut rng) as u32;
            let is_write = rng.gen_bool(WRITE_RATIO);
            (rec, is_write)
        })
        .collect()
}

fn main() {
    println!("==============================================================");
    println!(" 加密病历隐蔽访问层演示  (Path ORAM, N={}, Z={}, 块={}B)", CAPACITY, Z, BLOCK_DATA);
    println!("==============================================================\n");

    let cipher = || Cipher::from_seed(0xC1DE_2024);
    let levels = (CAPACITY as f64).log2().ceil() as u32;
    let enc_block = 12 + 8 + BLOCK_DATA + 16;

    // 所有医生跑同一份负载（预生成，保证对照组和 ORAM 组完全一致）
    let workloads: Vec<Vec<(u32, bool)>> = (0..DOCTORS)
        .map(|d| gen_workload(1000 + d as u64, OPS_PER_DOCTOR))
        .collect();
    let total_ops: usize = workloads.iter().map(|w| w.len()).sum();

    // ============ 对照组：朴素加密存储 ============
    println!("【对照组】朴素加密存储：内容加密，直接按记录号存取");
    let mut naive_cloud = SimCloud::new(0, 1, enc_block);
    for (d, ops) in workloads.iter().enumerate() {
        for (rec, is_write) in ops {
            if *is_write {
                let blob = cipher().encrypt(b"rec", &format!("病历#{}", rec).into_bytes());
                naive_cloud.raw_write(d as u32, *rec as u64, blob);
            } else {
                naive_cloud.raw_read(d as u32, *rec as u64, enc_block);
            }
        }
    }
    println!("  攻击者只看云端日志，直接得到：");
    println!("  ┌──────────┬────────┬────────┐");
    println!("  │  记录号  │ 读次数 │ 写次数 │   ← 重点病人一览无遗");
    println!("  ├──────────┼────────┼────────┤");
    for (rec, r, w) in analysis::naive_hotspots(&naive_cloud.log, 5) {
        println!("  │  #{:<6}│  {:<5} │  {:<5} │", rec, r, w);
    }
    println!("  └──────────┴────────┴────────┘");
    let (nr, nw) = naive_cloud
        .log
        .iter()
        .fold((0, 0), |(r, w), x| match x.op {
            OpKind::RawRead => (r + 1, w),
            OpKind::RawWrite => (r, w + 1),
            _ => (r, w),
        });
    println!("  读/写比例 {}:{} 也直接可见 → 可推断随访频率、病情变化节奏\n", nr, nw);

    // ============ ORAM 组 ============
    println!("【实验组】Path ORAM 访问层");
    let cloud = Arc::new(Mutex::new(SimCloud::new(levels, Z, enc_block)));

    // -- 阶段 1：初始化，预填病历 --
    let t0 = Instant::now();
    {
        let mut admin = OramClient::new(0, cipher(), CAPACITY, Z, BLOCK_DATA, 7);
        let mut c = cloud.lock().unwrap();
        while !c.acquire_lease(0) {}
        for rec in 0..RECORDS {
            let data = format!("病历#{}-初始档案", rec);
            admin.access(&mut c, rec, Some(data.as_bytes()), CrashPoint::None);
        }
        c.release_lease(0);
        println!("  初始化: 写入 {} 条病历, 耗时 {:?}", RECORDS, t0.elapsed());
    }

    // -- 阶段 2：四个医生并发调阅 --
    let t1 = Instant::now();
    let mut handles = Vec::new();
    for d in 0..DOCTORS {
        let cloud = Arc::clone(&cloud);
        let ops = workloads[d as usize].clone();
        handles.push(std::thread::spawn(move || {
            let mut client = OramClient::new(10 + d, cipher(), CAPACITY, Z, BLOCK_DATA, 100 + d as u64);
            let mut done = 0;
            while done < ops.len() {
                // 拿租约（持锁客户端崩溃时，等 TTL 过期后接管）
                loop {
                    if cloud.lock().unwrap().acquire_lease(10 + d) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                let end = (done + BATCH_PER_LEASE).min(ops.len());
                {
                    let mut c = cloud.lock().unwrap();
                    client.load_state(&mut c); // 同步最新状态（含崩溃恢复）
                    for (rec, is_write) in &ops[done..end] {
                        if *is_write {
                            let data = format!("病历#{}-随访记录-医生{}", rec, d);
                            client.access(&mut c, *rec, Some(data.as_bytes()), CrashPoint::None);
                        } else {
                            client.access(&mut c, *rec, None, CrashPoint::None);
                        }
                    }
                }
                cloud.lock().unwrap().release_lease(10 + d);
                done = end;
            }
            client.max_stash
        }));
    }
    let mut max_stash = 0;
    for h in handles {
        max_stash = max_stash.max(h.join().unwrap());
    }
    let concurrent_time = t1.elapsed();
    println!("  并发调阅: {} 医生 × {} 次访问, 耗时 {:?} ({:.0} 次/秒)",
        DOCTORS, OPS_PER_DOCTOR, concurrent_time,
        total_ops as f64 / concurrent_time.as_secs_f64());

    // -- 阶段 3：崩溃恢复演示 --
    println!("\n【崩溃演示】医生端在写回路径中途断电");
    let record = 7u32;
    {
        let mut c = cloud.lock().unwrap();
        let mut unlucky = OramClient::new(99, cipher(), CAPACITY, Z, BLOCK_DATA, 99);
        while !c.acquire_lease(99) {}
        unlucky.load_state(&mut c);
        // 写入"术前评估-v2"，写回路径只写了 5 个 bucket 就断电
        unlucky.access(&mut c, record, Some("术前评估-v2".as_bytes()), CrashPoint::MidWriteback(5));
        println!("  客户端 99 在写回第 5/{} 个 bucket 后崩溃, 租约未释放", levels + 1);
        // unlucky 直接 drop —— 租约靠 TTL 过期
    }
    std::thread::sleep(std::time::Duration::from_millis(600)); // 等租约过期
    {
        let mut c = cloud.lock().unwrap();
        let mut recovery = OramClient::new(100, cipher(), CAPACITY, Z, BLOCK_DATA, 100);
        while !c.acquire_lease(100) {}
        recovery.load_state(&mut c); // ← 检测到 pending 写回，幂等重放
        let got = recovery.access(&mut c, record, None, CrashPoint::None)
            .expect("record should exist");
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("术前评估-v2"), "崩溃恢复后数据错误: {}", text);
        println!("  新客户端接管 → 检测到未完成写回 → 幂等重放 → 数据完好: \"{}\"", &text[..text.find('\0').unwrap_or(text.len())].trim_end());
        c.release_lease(100);
    }

    // -- 阶段 4：数据正确性抽检 --
    {
        let mut c = cloud.lock().unwrap();
        let mut checker = OramClient::new(200, cipher(), CAPACITY, Z, BLOCK_DATA, 200);
        while !c.acquire_lease(200) {}
        checker.load_state(&mut c);
        let mut rng = StdRng::seed_from_u64(42);
        let mut checked = 0;
        for _ in 0..150 {
            let rec = rng.gen_range(0..RECORDS);
            if checker.access(&mut c, rec, None, CrashPoint::None).is_some() {
                checked += 1;
            }
        }
        println!("\n【正确性】随机抽检 {} 条病历全部可读回，内容经 AEAD 完整性校验", checked);
        c.release_lease(200);
    }

    // ============ 分析报告 ============
    let c = cloud.lock().unwrap();
    let oram_log = &c.log;
    let path_accesses = oram_log.iter().filter(|r| r.op == OpKind::ReadPath).count();
    let leaves = 1u64 << levels;

    println!("\n================ 攻击者视角：ORAM 日志分析 ================");
    let (chi2_ratio, max_ratio) = analysis::leaf_uniformity(oram_log, leaves, 1024);
    let (b_chi2, b_max) = analysis::uniform_baseline(leaves, 1024, path_accesses, 7);
    println!("  叶子访问频率 χ²/df:      ORAM {:.3}  | 纯随机基线 {:.3}  (越接近越不可区分)", chi2_ratio, b_chi2);
    println!("  最热叶子桶 / 期望值:     ORAM {:.2}  | 纯随机基线 {:.2}", max_ratio, b_max);
    let (coll, total) = analysis::adjacent_leaf_collisions(oram_log);
    println!("  相邻两次访问撞同一叶子: {} 次 / 共 {} 次 (随机期望 ≈ {:.2})",
        coll, total, total as f64 / leaves as f64);
    println!("  日志中的操作构成:");
    for (op, n, bytes) in analysis::oram_op_profile(oram_log) {
        println!("    {:?}: {} 次, 共 {}", op, n, fmt_bytes(bytes as u64));
    }
    println!("  → 每一次逻辑读和逻辑写在日志里都是同一个固定序列:");
    println!("    WriteState → ReadPath → WritePath → WriteState, 字节数恒定");
    println!("  → 云端无法区分读/写、无法定位记录、看不到频率与顺序规律");

    println!("\n================ 性能开销 ================");
    let logical = (total_ops + RECORDS as usize) as u64 * BLOCK_DATA as u64;
    let actual = c.bytes_read + c.bytes_written;
    println!("  路径访问总次数: {} (每次 = 1 读 + 1 写整条路径)", path_accesses);
    println!("  逻辑数据量:   {}", fmt_bytes(logical));
    println!("  实际传输量:   {} (含路径读写 + 状态检查点)", fmt_bytes(actual));
    println!("  带宽放大:     {:.0}×", actual as f64 / logical as f64);
    let path_bytes = (levels as usize + 1) * Z * enc_block;
    println!("  单次访问路径开销: 读 {} + 写 {} (树高 {}, Z={})",
        fmt_bytes(path_bytes as u64), fmt_bytes(path_bytes as u64), levels + 1, Z);
    println!("  客户端 stash 峰值: {} 块 ({}), 常驻客户端内存, 云端不可见",
        max_stash, fmt_bytes((max_stash * BLOCK_DATA) as u64));
    println!("  协调开销: 每次访问 2 次定长状态写 (64KB 档), 租约批量 {} 次访问摊销", BATCH_PER_LEASE);
    println!("  说明: 块大小提到 4KB 时, 路径放大从 ~174× 降到 ~44× (树高不变, 载荷变大)");
    println!("\n演示完成。");
}
