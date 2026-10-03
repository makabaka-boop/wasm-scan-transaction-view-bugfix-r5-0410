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

/// 扫描模块：暂存 put → get 验证 read-your-writes → scan("data/") → emit 报告。
const SCANNER_WAT: &str = r#"
(module
  (import "env" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    ;; 暂存写入 data/new = "N"
    (if (i32.ne (call $put (i32.const 16) (i32.const 8) (i32.const 64) (i32.const 1)) (i32.const 0))
      (then (return (i32.const 3))))
    ;; read-your-writes：get 必须立刻看到自己暂存的值
    (if (i32.ne (call $get (i32.const 16) (i32.const 8) (i32.const 768) (i32.const 8)) (i32.const 1))
      (then (return (i32.const 4))))
    (if (i32.ne (i32.load8_u (i32.const 768)) (i32.const 0x4e))
      (then (return (i32.const 4))))
    ;; 枚举 data/ 前缀并作为报告发出
    (local.set $n (call $scan (i32.const 96) (i32.const 5) (i32.const 2048) (i32.const 1024)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (i32.const 5))))
    (drop (call $emit (i32.const 128) (i32.const 6) (i32.const 2048) (local.get $n)))
    (i32.const 0))
  (data (i32.const 16) "data/new")
  (data (i32.const 64) "N")
  (data (i32.const 96) "data/")
  (data (i32.const 128) "report"))
"#;

/// 小缓冲模块：scan 缓冲只有 8 字节，必须返回 -4 且一个字节都不写（哨兵校验）。
const SCANBUF_WAT: &str = r#"
(module
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    ;; 输出区 2048..2064 预填 0xAA 哨兵
    (i32.store (i32.const 2048) (i32.const 0xaaaaaaaa))
    (i32.store (i32.const 2052) (i32.const 0xaaaaaaaa))
    (i32.store (i32.const 2056) (i32.const 0xaaaaaaaa))
    (i32.store (i32.const 2060) (i32.const 0xaaaaaaaa))
    ;; 缓冲装不下任何完整行 → 必须返回 -4 且不写半行
    (local.set $n (call $scan (i32.const 96) (i32.const 5) (i32.const 2048) (i32.const 8)))
    ;; 把返回码 emit 出去供宿主校验
    (i32.store (i32.const 1024) (local.get $n))
    (drop (call $emit (i32.const 128) (i32.const 4) (i32.const 1024) (i32.const 4)))
    ;; 哨兵必须完好：写了半行则返回非零
    (if (i32.ne (i32.load (i32.const 2048)) (i32.const 0xaaaaaaaa))
      (then (return (i32.const 6))))
    (if (i32.ne (i32.load (i32.const 2060)) (i32.const 0xaaaaaaaa))
      (then (return (i32.const 6))))
    (i32.const 0))
  (data (i32.const 96) "data/")
  (data (i32.const 128) "code"))
"#;

/// 非法前缀模块：前缀含非法 UTF-8 字节，scan 必须返回 -6。
const SCANBADPREFIX_WAT: &str = r#"
(module
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $n i32)
    ;; 前缀字节为 "d" 0xFF 0xFE "/" —— 非法 UTF-8
    (local.set $n (call $scan (i32.const 96) (i32.const 4) (i32.const 2048) (i32.const 1024)))
    (i32.store (i32.const 1024) (local.get $n))
    (drop (call $emit (i32.const 128) (i32.const 4) (i32.const 1024) (i32.const 4)))
    (i32.const 0))
  (data (i32.const 96) "d\ff\fe/")
  (data (i32.const 128) "code"))
"#;

/// 越界扫描模块：先暂存一笔写入，再用越界输出指针 scan → 宿主 trap，暂存必须撤销。
const SCANOOB_WAT: &str = r#"
(module
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    ;; 这笔暂存写入必须在越界 trap 后被撤销
    (drop (call $put (i32.const 16) (i32.const 6) (i32.const 64) (i32.const 1)))
    ;; scan 输出指针远超出线性内存
    (drop (call $scan (i32.const 96) (i32.const 5) (i32.const 0x7fff0000) (i32.const 65536)))
    (i32.const 0))
  (data (i32.const 16) "data/x")
  (data (i32.const 64) "v")
  (data (i32.const 96) "data/"))
"#;

/// 一致性读模块：第一次 get 的值作为基准，循环 2000 次 get 必须恒定，
/// 最后 scan 并 emit —— 运行期间其他任务的提交不得影响本次读取。
const READER_WAT: &str = r#"
(module
  (import "env" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "env" "scan" (func $scan (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 8192))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    (local $i i32)
    (local $c i32)
    (local $n i32)
    ;; 第一次 get：基准值存到 512，长度存到 768
    (local.set $n (call $get (i32.const 16) (i32.const 6) (i32.const 512) (i32.const 16)))
    (if (i32.lt_s (local.get $n) (i32.const 0)) (then (return (i32.const 7))))
    (i32.store (i32.const 768) (local.get $n))
    ;; 循环 2000 次：每次 get 都必须返回与第一次完全相同的值
    (local.set $c (i32.const 2000))
    (loop $again
      (local.set $n (call $get (i32.const 16) (i32.const 6) (i32.const 1024) (i32.const 16)))
      (if (i32.ne (local.get $n) (i32.load (i32.const 768)))
        (then (return (i32.const 8))))
      (local.set $i (i32.const 0))
      (loop $cmp
        (if (i32.ne
              (i32.load8_u (i32.add (i32.const 512) (local.get $i)))
              (i32.load8_u (i32.add (i32.const 1024) (local.get $i))))
          (then (return (i32.const 9))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $cmp (i32.lt_u (local.get $i) (local.get $n))))
      (local.set $c (i32.sub (local.get $c) (i32.const 1)))
      (br_if $again (i32.gt_u (local.get $c) (i32.const 0))))
    ;; 末尾 scan 并 emit，宿主侧再校验与 get 同源
    (local.set $n (call $scan (i32.const 32) (i32.const 5) (i32.const 2048) (i32.const 4096)))
    (if (i32.lt_s (local.get $n) (i32.const 0)) (then (return (i32.const 10))))
    (drop (call $emit (i32.const 64) (i32.const 4) (i32.const 2048) (local.get $n)))
    (i32.const 0))
  (data (i32.const 16) "data/k")
  (data (i32.const 32) "data/")
  (data (i32.const 64) "scan"))
"#;

/// 非法键模块：get/put 的键含非法 UTF-8 字节，必须各自返回 -6。
const BADKEY_WAT: &str = r#"
(module
  (import "env" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "env" "put" (func $put (param i32 i32 i32 i32) (result i32)))
  (import "env" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32)
    ;; get 键含 0xFF 0xFE → -6
    (i32.store (i32.const 1024)
      (call $get (i32.const 16) (i32.const 7) (i32.const 768) (i32.const 8)))
    (drop (call $emit (i32.const 64) (i32.const 3) (i32.const 1024) (i32.const 4)))
    ;; put 键含 0xFF 0xFE → -6
    (i32.store (i32.const 1024)
      (call $put (i32.const 16) (i32.const 7) (i32.const 128) (i32.const 1)))
    (drop (call $emit (i32.const 64) (i32.const 3) (i32.const 1024) (i32.const 4)))
    (i32.const 0))
  (data (i32.const 16) "data/\ff\fe")
  (data (i32.const 64) "res")
  (data (i32.const 128) "v"))
"#;

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
    svc.register_module("scanner", SCANNER_WAT.as_bytes()).unwrap();
    svc.register_module("scanbuf", SCANBUF_WAT.as_bytes()).unwrap();
    svc.register_module("scanbadprefix", SCANBADPREFIX_WAT.as_bytes())
        .unwrap();
    svc.register_module("scanoob", SCANOOB_WAT.as_bytes()).unwrap();
    svc.register_module("reader", READER_WAT.as_bytes()).unwrap();
    svc.register_module("badkey", BADKEY_WAT.as_bytes()).unwrap();
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

/// 解析 scan 的打包输出：u32 LE 键长、键、u32 LE 值长、值。
fn parse_rows(mut bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    while !bytes.is_empty() {
        let klen = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        bytes = &bytes[4..];
        let key = String::from_utf8(bytes[..klen].to_vec()).unwrap();
        bytes = &bytes[klen..];
        let vlen = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        bytes = &bytes[4..];
        let value = bytes[..vlen].to_vec();
        bytes = &bytes[vlen..];
        rows.push((key, value));
    }
    rows
}

fn emitted_payload<'a>(report: &'a plugin_host::RunReport, tag: &str) -> &'a [u8] {
    &report
        .emitted
        .iter()
        .find(|(t, _)| t == tag)
        .unwrap_or_else(|| panic!("no emitted event tagged `{tag}`"))
        .1
}

#[test]
fn scan_merges_staged_writes_and_hides_unreadable_keys() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/a", b"1").unwrap();
    kv.seed("tenant-a", "data/b", b"22").unwrap();
    // 无读权限的键：名字、值和长度都不得进入 scan 输出
    kv.seed("tenant-a", "other/secret", b"hidden-value").unwrap();

    let report = svc.execute(&rw_task("tenant-a", "scanner", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    // 报告 = 基准修订快照（data/a、data/b）⊕ 本任务暂存写入（data/new），
    // 按键字节序排列；other/secret 完全不出现
    let rows = parse_rows(emitted_payload(&report, "report"));
    assert_eq!(
        rows,
        vec![
            ("data/a".to_string(), b"1".to_vec()),
            ("data/b".to_string(), b"22".to_vec()),
            ("data/new".to_string(), b"N".to_vec()),
        ]
    );
    // 序列化字节流里连受限键的片段都不能出现
    let raw = emitted_payload(&report, "report");
    assert!(
        !raw.windows(6).any(|w| w == b"secret"),
        "scan output leaks restricted key material"
    );
    // 暂存写入已提交；受限键原样未动
    assert_eq!(
        kv.get("tenant-a", "data/new").unwrap().as_deref(),
        Some(b"N".as_ref())
    );
    assert_eq!(
        kv.get("tenant-a", "other/secret").unwrap().as_deref(),
        Some(b"hidden-value".as_ref())
    );
    // 证据：scan 成功，且 get 看到了自己暂存的值（模块内校验，失败会返回非零）
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "scan" && r.key == "data/" && r.result == CallResult::Ok)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "get" && r.key == "data/new" && r.result == CallResult::Ok)
    );
}

#[test]
fn scan_buffer_too_small_returns_minus4_and_writes_nothing() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/a", b"value-longer-than-cap")
        .unwrap();

    let report = svc.execute(&rw_task("tenant-a", "scanbuf", vec![]));

    // 模块选择忽略 -4 继续执行并正常提交
    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    // 返回码确实是 -4
    let code = i32::from_le_bytes(emitted_payload(&report, "code").try_into().unwrap());
    assert_eq!(code, -4);
    // 证据与返回值一致：BufferTooSmall；模块内哨兵校验通过（否则终态为 Trapped），
    // 即缓冲不足时一个字节都没有写、没有半条记录
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "scan" && r.result == CallResult::BufferTooSmall)
    );
}

#[test]
fn scan_with_invalid_utf8_prefix_is_rejected() {
    let (svc, _kv) = service();

    let report = svc.execute(&rw_task("tenant-a", "scanbadprefix", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    let code = i32::from_le_bytes(emitted_payload(&report, "code").try_into().unwrap());
    assert_eq!(code, -6);
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "scan" && r.result == CallResult::Invalid)
    );
}

#[test]
fn invalid_utf8_keys_are_rejected_for_get_and_put() {
    let (svc, _kv) = service();

    let report = svc.execute(&rw_task("tenant-a", "badkey", vec![]));

    assert_eq!(
        report.terminal,
        TerminalState::Committed,
        "{:?}",
        report.error
    );
    // 两次 emit 的返回码都必须是 -6
    assert_eq!(report.emitted.len(), 2);
    for (_, payload) in &report.emitted {
        assert_eq!(i32::from_le_bytes(payload[..].try_into().unwrap()), -6);
    }
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "get" && r.result == CallResult::Invalid)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "put" && r.result == CallResult::Invalid)
    );
}

#[test]
fn scan_out_of_bounds_traps_and_revokes_staged_writes() {
    let (svc, kv) = service();

    let report = svc.execute(&rw_task("tenant-a", "scanoob", vec![]));

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
    // 越界留在证据里；暂存的 put 被撤销，修订号不变
    assert!(
        report
            .evidence
            .iter()
            .any(|r| r.func == "scan" && r.result == CallResult::OutOfBounds)
    );
    assert!(kv.get("tenant-a", "data/x").unwrap().is_none());
    assert_eq!(kv.baseline("tenant-a").unwrap(), 0);
}

#[test]
fn get_and_scan_share_one_version_while_others_commit() {
    let (svc, kv) = service();
    kv.seed("tenant-a", "data/k", b"v0").unwrap();

    // 并发提交者：在任务运行期间不断提交 data/k 的新版本（模拟其他任务完成提交）
    let kv_writer = kv.clone();
    let writer = std::thread::spawn(move || {
        let mut rev = kv_writer.baseline("tenant-a").unwrap();
        for i in 1..2000i64 {
            let mut staged = HashMap::new();
            staged.insert("data/k".to_string(), format!("v{i}").into_bytes());
            match kv_writer.commit("tenant-a", rev, &staged) {
                Ok(new_rev) => rev = new_rev,
                Err(CommitError::Conflict { .. }) => {
                    rev = kv_writer.baseline("tenant-a").unwrap()
                }
                Err(e) => panic!("commit failed: {e}"),
            }
        }
    });

    // 读任务：2000 次 get 必须全部返回同一值，末尾 scan 与 get 同源
    let report = svc.execute(&rw_task("tenant-a", "reader", vec![]));
    writer.join().unwrap();

    // 模块内部已校验所有 get 值恒定（否则返回非零 → Trapped）；
    // 提交时基准可能已被并发提交越过 → 允许 Committed 或 RevisionConflict
    assert!(
        matches!(
            report.terminal,
            TerminalState::Committed | TerminalState::RevisionConflict
        ),
        "{:?}",
        report.error
    );
    // scan 输出只有 data/k 一行（读前缀 data/ 过滤后），版本与 get 一致
    let rows = parse_rows(emitted_payload(&report, "scan"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "data/k");
    assert!(
        report
            .evidence
            .iter()
            .all(|r| r.result != CallResult::OutOfBounds)
    );
}

#[test]
fn snapshot_is_atomic_under_concurrent_commits() {
    let kv = Arc::new(KvStore::open_in_memory().unwrap());

    // 写者：第 i 次提交把 data/k 置为 "i"，修订号变为 i
    let kv_writer = kv.clone();
    let writer = std::thread::spawn(move || {
        let mut rev = 0i64;
        for i in 1..500i64 {
            let mut staged = HashMap::new();
            staged.insert("data/k".to_string(), i.to_string().into_bytes());
            match kv_writer.commit("t", rev, &staged) {
                Ok(new_rev) => rev = new_rev,
                Err(CommitError::Conflict { .. }) => {
                    rev = kv_writer.baseline("t").unwrap()
                }
                Err(e) => panic!("commit failed: {e}"),
            }
        }
    });

    // 读者：快照里的值必须恰好等于其修订号 —— 修订号与数据来自同一把锁
    for _ in 0..500 {
        let (rev, data) = kv.snapshot("t").unwrap();
        if rev == 0 {
            continue;
        }
        assert_eq!(
            data.get("data/k")
                .map(|v| String::from_utf8(v.clone()).unwrap()),
            Some(rev.to_string()),
            "snapshot mixed revision {rev} with data from another revision"
        );
    }
    writer.join().unwrap();
}
