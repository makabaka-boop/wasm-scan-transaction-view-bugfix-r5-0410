//! 集成测试：真实小型 Wasm 模块（WAT 编译）覆盖
//! 无限循环、越权键、错误指针、WASI 拒绝、输出上限、
//! 修订冲突与两个租户并发执行。

use plugin_host::{CallResult, CommitError, KvStore, Limits, PluginService, Task, TerminalState};
use std::collections::HashMap;
use std::sync::Arc;

/// 正常模块：get("data/config") → put("data/echo")；put("data/result", 输入)；emit("done", 输入)。
const OK_WAT: &str = r#"
(module
  (import "env" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param $in_ptr i32) (param $in_len i32) (result i32)
    (local $n i32)
    ;; n = get("data/config") 到暂存缓冲 768
    (local.set $n (call $get (i32.const 16) (i32.const 11) (i32.const 768) (i32.const 64)))
    ;; 找到则复制到 "data/echo"
    (if (i32.ge_s (local.get $n) (i32.const 0))
      (then
        (drop (call $put (i32.const 32) (i32.const 9) (i32.const 768) (local.get $n)))))
    ;; 把任务输入写入 "data/result"
    (drop (call $put (i32.const 48) (i32.const 11) (local.get $in_ptr) (local.get $in_len)))
    ;; 发出 "done" 事件，载荷为输入
    (drop (call $emit (i32.const 64) (i32.const 4) (local.get $in_ptr) (local.get $in_len)))
    (i32.const 0))
  (data (i32.const 16) "data/config")
  (data (i32.const 32) "data/echo")
  (data (i32.const 48) "data/result")
  (data (i32.const 64) "done"))
"#;

/// 无限循环模块：先暂存一个 put，然后空转烧光燃料。
const SPIN_WAT: &str = r#"
(module
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    ;; 这笔暂存写入必须在燃料耗尽后被撤销
    (drop (call $put (i32.const 16) (i32.const 6) (i32.const 64) (i32.const 1)))
    (loop $spin (br $spin))
    (i32.const 0))
  (data (i32.const 16) "data/x")
  (data (i32.const 64) "v"))
"#;

/// 越权模块：先试探越权 get，再暂存合法 put，最后越权 put 被拒后中止。
const UNAUTH_WAT: &str = r#"
(module
  (import "env" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    ;; 1. 读允许前缀之外的键必须被拒绝（返回非零）
    (if (i32.eqz (call $get (i32.const 32) (i32.const 12) (i32.const 512) (i32.const 16)))
      (then unreachable))
    ;; 2. 合法写入 —— 暂存；运行中止时必须被撤销
    (drop (call $put (i32.const 16) (i32.const 7) (i32.const 64) (i32.const 1)))
    ;; 3. 写允许前缀之外的键必须被拒绝；随后中止运行
    (if (i32.ne (call $put (i32.const 32) (i32.const 12) (i32.const 64) (i32.const 1)) (i32.const 0))
      (then unreachable))
    (i32.const 0))
  (data (i32.const 16) "data/ok")
  (data (i32.const 32) "other/secret")
  (data (i32.const 64) "v"))
"#;

/// 错误指针模块：键合法，但值指针远超出线性内存。
const BADPTR_WAT: &str = r#"
(module
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (drop (call $put (i32.const 16) (i32.const 6) (i32.const 0x7fff0000) (i32.const 0xffff)))
    (i32.const 0))
  (data (i32.const 16) "data/y"))
"#;

/// 请求 WASI 能力的模块：必须被拒绝实例化。
const WASI_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "run") (param i32 i32) (result i32) (i32.const 0)))
"#;

/// 扫描报告模块：先暂存 data/staged，再按 "data/" 枚举并把结果原样 emit 出来。
const SCAN_REPORT_WAT: &str = r#"
(module
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    ;; 先暂存自己的写入：data/staged = "STAGED!"
    (drop (call $put (i32.const 16) (i32.const 11) (i32.const 128) (i32.const 7)))
    ;; 按前缀 "data/" 枚举到 8192，容量 4096
    (local.set $n (call $scan (i32.const 32) (i32.const 5) (i32.const 8192) (i32.const 4096)))
    ;; 成功则把枚举结果原样 emit 出去，供测试解析
    (if (i32.ge_s (local.get $n) (i32.const 0))
      (then (drop (call $emit (i32.const 48) (i32.const 4) (i32.const 8192) (local.get $n)))))
    (i32.const 0))
  (data (i32.const 16) "data/staged")
  (data (i32.const 32) "data/")
  (data (i32.const 48) "scan")
  (data (i32.const 128) "STAGED!"))
"#;

/// 版本一致性模块：点读 → 长时间空转（留出并发提交窗口）→ 再点读 + 枚举，
/// 三次读取的结果分别暂存到 data/r1、data/r2、data/r3。
const CONSIST_WAT: &str = r#"
(module
  (import "env" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    (local $i i32)
    ;; 第一次点读 data/k → 暂存到 data/r1
    (local.set $n (call $get (i32.const 16) (i32.const 6) (i32.const 2048) (i32.const 64)))
    (if (i32.ge_s (local.get $n) (i32.const 0))
      (then (drop (call $put (i32.const 32) (i32.const 7) (i32.const 2048) (local.get $n)))))
    ;; 有限但漫长的空转：给并发写入者留出落在两次读取之间的窗口
    (local.set $i (i32.const 30000000))
    (loop $spin
      (local.set $i (i32.sub (local.get $i) (i32.const 1)))
      (br_if $spin (i32.gt_s (local.get $i) (i32.const 0))))
    ;; 第二次点读 → 暂存到 data/r2
    (local.set $n (call $get (i32.const 16) (i32.const 6) (i32.const 2048) (i32.const 64)))
    (if (i32.ge_s (local.get $n) (i32.const 0))
      (then (drop (call $put (i32.const 48) (i32.const 7) (i32.const 2048) (local.get $n)))))
    ;; 枚举 "data/" → 整个结果暂存到 data/r3
    (local.set $n (call $scan (i32.const 64) (i32.const 5) (i32.const 8192) (i32.const 4096)))
    (if (i32.ge_s (local.get $n) (i32.const 0))
      (then (drop (call $put (i32.const 80) (i32.const 7) (i32.const 8192) (local.get $n)))))
    (i32.const 0))
  (data (i32.const 16) "data/k")
  (data (i32.const 32) "data/r1")
  (data (i32.const 48) "data/r2")
  (data (i32.const 64) "data/")
  (data (i32.const 80) "data/r3"))
"#;

/// 小缓冲模块：枚举缓冲只有 4 字节，必须得到 -4 且哨兵字节原封不动。
const SMALLBUF_WAT: &str = r#"
(module
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    ;; 缓冲只有 4 字节，装不下任何完整记录 → 必须返回 -4
    (local.set $n (call $scan (i32.const 16) (i32.const 5) (i32.const 8192) (i32.const 4)))
    (if (i32.eq (local.get $n) (i32.const -4))
      (then (drop (call $put (i32.const 32) (i32.const 12) (i32.const 96) (i32.const 3)))))
    ;; 输出区哨兵必须原封不动（没有写半条记录）
    (if (i32.eq (i32.load8_u (i32.const 8192)) (i32.const 0xAA))
      (then (drop (call $put (i32.const 48) (i32.const 15) (i32.const 96) (i32.const 3)))))
    (i32.const 0))
  (data (i32.const 16) "data/")
  (data (i32.const 32) "data/rc-neg4")
  (data (i32.const 48) "data/no-partial")
  (data (i32.const 96) "yes")
  (data (i32.const 8192) "\AA\AA\AA\AA\AA\AA\AA\AA"))
"#;

/// 非法前缀模块：前缀含非法 UTF-8 字节，必须得到 -6 且不写输出。
const BADPREFIX_WAT: &str = r#"
(module
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    ;; 前缀是非法 UTF-8 字节 0xFF 0xFE → 必须返回 -6
    (local.set $n (call $scan (i32.const 16) (i32.const 2) (i32.const 8192) (i32.const 4096)))
    (if (i32.eq (local.get $n) (i32.const -6))
      (then (drop (call $put (i32.const 32) (i32.const 15) (i32.const 96) (i32.const 3)))))
    ;; 输出区哨兵必须原封不动
    (if (i32.eq (i32.load8_u (i32.const 8192)) (i32.const 0xAA))
      (then (drop (call $put (i32.const 48) (i32.const 15) (i32.const 96) (i32.const 3)))))
    (i32.const 0))
  (data (i32.const 16) "\FF\FE")
  (data (i32.const 32) "data/bad-prefix")
  (data (i32.const 48) "data/no-partial")
  (data (i32.const 96) "yes")
  (data (i32.const 8192) "\AA\AA\AA\AA"))
"#;

/// 枚举越界模块：先暂存一笔写入，再用远超线性内存的输出指针枚举。
const SCANOOB_WAT: &str = r#"
(module
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    ;; 这笔暂存写入必须在 scan 越界 trap 后被撤销
    (drop (call $put (i32.const 16) (i32.const 15) (i32.const 96) (i32.const 1)))
    ;; 输出指针远超线性内存 → 宿主拒绝并 trap
    (drop (call $scan (i32.const 32) (i32.const 5) (i32.const 0x7fff0000) (i32.const 4096)))
    (i32.const 0))
  (data (i32.const 16) "data/oob-staged")
  (data (i32.const 32) "data/")
  (data (i32.const 96) "v"))
"#;

/// 解析 scan 的打包输出：每行 u32 LE 键长度、键、u32 LE 值长度、值。
fn parse_rows(mut bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    while !bytes.is_empty() {
        let (klen, rest) = bytes.split_at(4);
        let klen = u32::from_le_bytes(klen.try_into().unwrap()) as usize;
        let (key, rest) = rest.split_at(klen);
        let (vlen, rest) = rest.split_at(4);
        let vlen = u32::from_le_bytes(vlen.try_into().unwrap()) as usize;
        let (val, rest) = rest.split_at(vlen);
        rows.push((String::from_utf8(key.to_vec()).unwrap(), val.to_vec()));
        bytes = rest;
    }
    rows
}

fn service() -> (Arc<PluginService>, Arc<KvStore>) {
    let kv = Arc::new(KvStore::open_in_memory().unwrap());
    let mut svc = PluginService::new(kv.clone()).unwrap();
    svc.register_module("ok", OK_WAT.as_bytes()).unwrap();
    svc.register_module("spin", SPIN_WAT.as_bytes()).unwrap();
    svc.register_module("unauth", UNAUTH_WAT.as_bytes())
        .unwrap();
    svc.register_module("badptr", BADPTR_WAT.as_bytes())
        .unwrap();
    svc.register_module("wasi", WASI_WAT.as_bytes()).unwrap();
    svc.register_module("scan-report", SCAN_REPORT_WAT.as_bytes())
        .unwrap();
    svc.register_module("consist", CONSIST_WAT.as_bytes())
        .unwrap();
    svc.register_module("smallbuf", SMALLBUF_WAT.as_bytes())
        .unwrap();
    svc.register_module("badprefix", BADPREFIX_WAT.as_bytes())
        .unwrap();
    svc.register_module("scanoob", SCANOOB_WAT.as_bytes())
        .unwrap();
    (Arc::new(svc), kv)
}

fn rw_task(tenant: &str, module: &str, input: Vec<u8>) -> Task {
    Task::new(tenant, module, input)
        .with_read_prefixes(&["data/"])
        .with_write_prefixes(&["data/"])
}

#[test]
fn happy_path_commits_and_returns_evidence() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/config", b"cfg-v1").unwrap();

    let report = svc.execute(&rw_task("tenant-a", "ok", b"hello-input".to_vec()));

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    assert_eq!(report.baseline_rev, 0);
    assert_eq!(report.committed_rev, Some(1));
    // 暂存写入已落库：派生键 + 输入键
    assert_eq!(
        kv.get("tenant-a", "data/echo").unwrap().as_deref(),
        Some(b"cfg-v1".as_ref())
    );
    assert_eq!(
        kv.get("tenant-a", "data/result").unwrap().as_deref(),
        Some(b"hello-input".as_ref())
    );
    // emit 输出随报告返回
    assert_eq!(
        report.emitted,
        vec![("done".to_string(), b"hello-input".to_vec())]
    );
    // 宿主调用证据完整：get、两个 put、emit
    assert_eq!(report.evidence.len(), 4);
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "get" && r.key == "data/config" && r.result == CallResult::Ok)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "put" && r.key == "data/result" && r.result == CallResult::Ok)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "emit" && r.key == "done" && r.result == CallResult::Ok)
    );
    assert!(report.fuel_consumed.unwrap() > 0);
}

#[test]
fn infinite_loop_runs_out_of_fuel_and_revokes_writes() {
    let (svc, kv) = service();

    let task = rw_task("tenant-a", "spin", vec![]).with_limits(Limits {
        fuel: 100_000,
        ..Default::default()
    });
    let report = svc.execute(&task);

    assert_eq!(
        report.terminal,
        TerminalState::FuelExhausted,
        "{:?}",
        report.error
    );
    // 循环前暂存的 put 被撤销，修订号不变
    assert!(kv.get("tenant-a", "data/x").unwrap().is_none());
    assert_eq!(kv.baseline("tenant-a").unwrap(), 0);
    // 证据里能看到那笔被撤销的暂存写入
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "put" && r.key == "data/x" && r.result == CallResult::Ok)
    );
}

#[test]
fn unauthorized_key_is_denied_and_run_aborts() {
    let (svc, kv) = service();

    let report = svc.execute(&rw_task("tenant-a", "unauth", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Trapped,
        "{:?}",
        report.error
    );
    // 越权读写都在证据中留下 Denied 记录
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "get" && r.key == "other/secret" && r.result == CallResult::Denied)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "put" && r.key == "other/secret" && r.result == CallResult::Denied)
    );
    // 之前的合法暂存写入也一并撤销
    assert!(kv.get("tenant-a", "data/ok").unwrap().is_none());
    assert!(kv.get("tenant-a", "other/secret").unwrap().is_none());
    assert_eq!(kv.baseline("tenant-a").unwrap(), 0);
}

#[test]
fn bad_pointer_is_caught_by_host_bounds_check() {
    let (svc, kv) = service();

    let report = svc.execute(&rw_task("tenant-a", "badptr", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::HostError,
        "{:?}",
        report.error
    );
    assert!(
        report.error.as_deref().unwrap().contains("out of bounds"),
        "unexpected error: {:?}",
        report.error
    );
    // 越界尝试留在证据里，但没有任何写入落库
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "put" && r.key == "data/y" && r.result == CallResult::OutOfBounds)
    );
    assert!(kv.get("tenant-a", "data/y").unwrap().is_none());
    assert_eq!(kv.baseline("tenant-a").unwrap(), 0);
}

#[test]
fn wasi_import_is_rejected() {
    let (svc, _kv) = service();

    let report = svc.execute(&rw_task("tenant-a", "wasi", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Rejected,
        "{:?}",
        report.error
    );
    assert!(
        report
            .error
            .as_deref()
            .unwrap()
            .contains("wasi_snapshot_preview1"),
        "unexpected error: {:?}",
        report.error
    );
}

#[test]
fn output_limit_is_enforced() {
    let (svc, _kv) = service();

    // 输入 128 字节，但 emit 输出上限只有 16 字节
    let task = rw_task("tenant-a", "ok", vec![b'x'; 128]).with_limits(Limits {
        max_output_bytes: 16,
        ..Default::default()
    });
    let report = svc.execute(&task);

    // 模块选择忽略 emit 错误码继续执行并提交
    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    assert!(report.emitted.is_empty());
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "emit" && r.result == CallResult::OutputLimited)
    );
}

#[test]
fn revision_conflict_revokes_writes() {
    let kv = KvStore::open_in_memory().unwrap();

    let mut staged = HashMap::new();
    staged.insert("data/a".to_string(), b"1".to_vec());
    assert_eq!(kv.commit("t", 0, &staged).unwrap(), 1);

    // 第二个提交仍基于旧基准 0：冲突，什么都不应用
    let mut staged2 = HashMap::new();
    staged2.insert("data/b".to_string(), b"2".to_vec());
    let err = kv.commit("t", 0, &staged2).unwrap_err();
    assert!(matches!(err, CommitError::Conflict { .. }));
    assert!(kv.get("t", "data/b").unwrap().is_none());
    assert_eq!(
        kv.get("t", "data/a").unwrap().as_deref(),
        Some(b"1".as_ref())
    );
    assert_eq!(kv.baseline("t").unwrap(), 1);
}

#[test]
fn two_tenants_run_concurrently() {
    let (svc, kv) = service();

    let mut handles = Vec::new();
    for (tenant, tag) in [("tenant-a", "A"), ("tenant-b", "B")] {
        let svc = svc.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..8 {
                let input = format!("{tag}-{i}").into_bytes();
                let report = svc.execute(&rw_task(tenant, "ok", input));
                assert_eq!(
                    report.terminal,
                    TerminalState::Committed,
                    "tenant {tenant} iter {i}: {:?}",
                    report.error
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // 两个租户各自提交 8 次，互不冲突
    assert_eq!(kv.baseline("tenant-a").unwrap(), 8);
    assert_eq!(kv.baseline("tenant-b").unwrap(), 8);
    // 命名空间隔离：同名键各存各的值
    assert_eq!(
        kv.get("tenant-a", "data/result").unwrap().as_deref(),
        Some(b"A-7".as_ref())
    );
    assert_eq!(
        kv.get("tenant-b", "data/result").unwrap().as_deref(),
        Some(b"B-7".as_ref())
    );
}

#[test]
fn scan_filters_unreadable_keys_and_includes_own_staged_writes() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/a", b"A").unwrap();
    kv.seed("tenant-a", "data/b", b"BB").unwrap();
    // 扫描前缀 "data/" 能匹配、但读权限不覆盖的键
    kv.seed("tenant-a", "data/hidden", b"HIDDEN").unwrap();
    // 扫描前缀之外的键
    kv.seed("tenant-a", "secret/x", b"TOPSECRET").unwrap();

    let task = Task::new("tenant-a", "scan-report", vec![])
        .with_read_prefixes(&["data/a", "data/b", "data/staged"])
        .with_write_prefixes(&["data/"]);
    let report = svc.execute(&task);

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    // 枚举结果：只含可读键，且包含本次任务自己暂存的 data/staged
    assert_eq!(report.emitted.len(), 1);
    assert_eq!(report.emitted[0].0, "scan");
    let rows = parse_rows(&report.emitted[0].1);
    assert_eq!(
        rows,
        vec![
            ("data/a".to_string(), b"A".to_vec()),
            ("data/b".to_string(), b"BB".to_vec()),
            ("data/staged".to_string(), b"STAGED!".to_vec()),
        ],
        "scan 必须按键序输出可读键并叠加暂存写入"
    );
    // 受限键的名字与值字节都不出现在输出里 —— 行数与总字节数精确匹配，
    // 说明连长度字段都没有泄漏
    let blob = &report.emitted[0].1;
    assert!(!blob.windows(6).any(|w| w == b"hidden"));
    assert!(!blob.windows(6).any(|w| w == b"HIDDEN"));
    assert!(!blob.windows(6).any(|w| w == b"secret"));
    assert!(report
        .evidence
        .iter()
        .any(|r| r.func == "scan" && r.key == "data/" && r.result == CallResult::Ok));
    // 暂存写入随任务成功一并落库
    assert_eq!(
        kv.get("tenant-a", "data/staged").unwrap().as_deref(),
        Some(b"STAGED!".as_ref())
    );
}

#[test]
fn reads_within_a_task_observe_one_consistent_version() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/k", b"V1").unwrap();

    let task = Task::new("tenant-a", "consist", vec![])
        .with_read_prefixes(&["data/"])
        .with_write_prefixes(&["data/"])
        .with_limits(Limits {
            fuel: 400_000_000,
            ..Default::default()
        });

    let svc2 = svc.clone();
    let handle = std::thread::spawn(move || svc2.execute(&task));

    // 任务执行中途，另一个写入者把 data/k 改成 V2（不推进修订号，
    // 模拟数据在本任务的读取窗口内被改动；提交冲突路径由其它测试覆盖）。
    // 无论这次写入落在快照之前还是之后，同一任务内的读取都必须自洽。
    std::thread::sleep(std::time::Duration::from_millis(30));
    kv.seed("tenant-a", "data/k", b"V2").unwrap();

    let report = handle.join().unwrap();
    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );

    let r1 = kv.get("tenant-a", "data/r1").unwrap().expect("r1 committed");
    let r2 = kv.get("tenant-a", "data/r2").unwrap().expect("r2 committed");
    let r3 = kv.get("tenant-a", "data/r3").unwrap().expect("r3 committed");
    // 同一任务内的两次点读必须对应同一版本
    assert_eq!(r1, r2, "point reads within one task diverged");
    assert!(
        r1 == b"V1" || r1 == b"V2",
        "unexpected value: {r1:?}"
    );
    // 枚举结果中的 data/k 必须与点读一致
    let rows = parse_rows(&r3);
    let scanned = rows
        .iter()
        .find(|(k, _)| k == "data/k")
        .map(|(_, v)| v.clone())
        .expect("scan output must contain data/k");
    assert_eq!(scanned, r1, "scan and get observed different versions");
    // 枚举同样能看到本次任务自己暂存的 r1/r2
    assert!(rows.iter().any(|(k, _)| k == "data/r1"));
    assert!(rows.iter().any(|(k, _)| k == "data/r2"));
}

#[test]
fn scan_buffer_too_small_writes_nothing_and_records_evidence() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/a", b"A").unwrap();

    let report = svc.execute(&rw_task("tenant-a", "smallbuf", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    // 模块在 guest 内验证：返回码确为 -4，且输出区哨兵未被破坏（没写半条记录）
    assert_eq!(
        kv.get("tenant-a", "data/rc-neg4").unwrap().as_deref(),
        Some(b"yes".as_ref())
    );
    assert_eq!(
        kv.get("tenant-a", "data/no-partial").unwrap().as_deref(),
        Some(b"yes".as_ref())
    );
    // 失败调用也留在证据里
    assert!(report
        .evidence
        .iter()
        .any(|r| r.func == "scan" && r.result == CallResult::BufferTooSmall));
}

#[test]
fn scan_rejects_invalid_utf8_prefix_and_records_evidence() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/a", b"A").unwrap();

    let report = svc.execute(&rw_task("tenant-a", "badprefix", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    // 模块在 guest 内验证：返回码确为 -6，且输出区未被写入
    assert_eq!(
        kv.get("tenant-a", "data/bad-prefix").unwrap().as_deref(),
        Some(b"yes".as_ref())
    );
    assert_eq!(
        kv.get("tenant-a", "data/no-partial").unwrap().as_deref(),
        Some(b"yes".as_ref())
    );
    assert!(report
        .evidence
        .iter()
        .any(|r| r.func == "scan" && r.result == CallResult::Invalid));
}

#[test]
fn scan_out_of_bounds_traps_and_revokes_staged_writes() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/a", b"A").unwrap();

    let report = svc.execute(&rw_task("tenant-a", "scanoob", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::HostError,
        "{:?}",
        report.error
    );
    // 越界调用留在证据里，但暂存写入全部撤销、修订号不变
    assert!(report
        .evidence
        .iter()
        .any(|r| r.func == "scan" && r.result == CallResult::OutOfBounds));
    assert!(kv.get("tenant-a", "data/oob-staged").unwrap().is_none());
    assert_eq!(kv.baseline("tenant-a").unwrap(), 0);
}

#[test]
fn snapshot_is_atomic_and_point_in_time() {
    let kv = KvStore::open_in_memory().unwrap();
    kv.seed("t", "data/a", b"1").unwrap();

    let (rev, snap) = kv.snapshot("t").unwrap();
    assert_eq!(rev, 0);
    assert_eq!(snap.get("data/a").map(|v| v.as_slice()), Some(b"1".as_ref()));

    // 之后的提交不影响已取得的快照
    let mut staged = HashMap::new();
    staged.insert("data/a".to_string(), b"2".to_vec());
    assert_eq!(kv.commit("t", 0, &staged).unwrap(), 1);
    assert_eq!(snap.get("data/a").map(|v| v.as_slice()), Some(b"1".as_ref()));

    // 新快照反映新版本
    let (rev2, snap2) = kv.snapshot("t").unwrap();
    assert_eq!(rev2, 1);
    assert_eq!(snap2.get("data/a").map(|v| v.as_slice()), Some(b"2".as_ref()));
}
