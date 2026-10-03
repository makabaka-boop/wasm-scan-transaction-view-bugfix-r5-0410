//! 宿主函数与每任务执行上下文。
//!
//! 模块只能导入这里的 `get` / `put` / `scan` / `emit`。所有宿主函数：
//!  - 只访问当前调用者自己的 [`TaskCtx`]（该任务自己的上下文）；
//!  - 读取同一份基准修订快照，并叠加本任务的暂存写入（read-your-writes），
//!    因此同一次执行里 `get` 与 `scan` 看到的已提交数据是同一版本；
//!  - `scan` 与 `get` 权限一致：逐键按读前缀过滤，不可读键的名字、值
//!    和条目长度都不会进入输出；
//!  - 对 guest 指针做严格的边界检查，越界即返回 [`OobError`]，
//!    wasmtime 会将其转为 trap，从而中止执行并撤销全部暂存写入；
//!  - 把每次调用（包括失败调用）的结果记录进证据列表，随运行报告返回。

use std::collections::HashMap;
use std::fmt;
use wasmtime::{Caller, Memory, StoreLimits};

/// 返回给 guest 的宿主调用错误码（负值）。
pub const ERR_DENIED: i32 = -2;
pub const ERR_OUTPUT_LIMIT: i32 = -3;
pub const ERR_BUF_TOO_SMALL: i32 = -4;
pub const ERR_NOT_FOUND: i32 = -5;
pub const ERR_INVALID: i32 = -6;

/// guest 指针越界。宿主函数返回该错误 → wasmtime 转为 trap → 撤销写入。
#[derive(Debug)]
pub struct OobError {
    pub func: &'static str,
    pub ptr: i32,
    pub len: i32,
}

impl fmt::Display for OobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "guest pointer out of bounds in host call `{}` (ptr={:#x}, len={:#x})",
            self.func, self.ptr, self.len
        )
    }
}

impl std::error::Error for OobError {}

/// 单次宿主调用的结果，进入证据列表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallResult {
    Ok,
    Denied,
    NotFound,
    BufferTooSmall,
    OutputLimited,
    OutOfBounds,
    Invalid,
}

/// 一次宿主调用的证据记录。
#[derive(Debug, Clone)]
pub struct HostCallRecord {
    pub func: &'static str,
    pub key: String,
    pub value_len: usize,
    pub result: CallResult,
}

/// 每任务执行上下文。宿主函数只能触达它 —— 即当前实例所属任务的上下文。
pub struct TaskCtx {
    pub tenant: String,
    pub read_prefixes: Vec<String>,
    pub write_prefixes: Vec<String>,
    /// 输入基准修订对应的已提交快照：本次执行所有读取的版本来源，
    /// 不受其他任务中途提交影响。
    pub snapshot: HashMap<String, Vec<u8>>,
    /// 暂存写入：读取时叠加在快照之上；正常返回后才按基准修订号一次性提交。
    pub staged: HashMap<String, Vec<u8>>,
    pub evidence: Vec<HostCallRecord>,
    pub emitted: Vec<(String, Vec<u8>)>,
    pub emitted_bytes: usize,
    pub max_output_bytes: usize,
    pub store_limits: StoreLimits,
    /// 实例化后由宿主填入的模块线性内存句柄。
    pub memory: Option<Memory>,
}

fn allowed(prefixes: &[String], key: &str) -> bool {
    prefixes.iter().any(|p| key.starts_with(p.as_str()))
}

fn record(
    caller: &mut Caller<'_, TaskCtx>,
    func: &'static str,
    key: String,
    value_len: usize,
    result: CallResult,
) {
    caller.data_mut().evidence.push(HostCallRecord {
        func,
        key,
        value_len,
        result,
    });
}

/// 对 guest 内存做边界检查的读取。任何越界都是 [`OobError`]（→ trap）。
fn read_guest(
    caller: &Caller<'_, TaskCtx>,
    func: &'static str,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, OobError> {
    let oob = || OobError { func, ptr, len };
    if ptr < 0 || len < 0 {
        return Err(oob());
    }
    let mem = caller.data().memory.ok_or_else(oob)?;
    let data = mem.data(caller);
    let start = ptr as usize;
    let end = start.checked_add(len as usize).ok_or_else(oob)?;
    data.get(start..end).map(|s| s.to_vec()).ok_or_else(oob)
}

/// 读取 guest 提供的键/前缀字节并严格校验 UTF-8。
/// 静默做有损替换会让不同字节序列别名到同一个键（含 U+FFFD），
/// 使插件读到或枚举到意料之外的键区间，因此非法编码一律拒绝。
fn read_key(
    caller: &mut Caller<'_, TaskCtx>,
    func: &'static str,
    ptr: i32,
    len: i32,
) -> wasmtime::Result<Result<String, i32>> {
    let bytes = match read_guest(caller, func, ptr, len) {
        Ok(b) => b,
        Err(e) => {
            record(caller, func, String::new(), 0, CallResult::OutOfBounds);
            return Err(e.into());
        }
    };
    match String::from_utf8(bytes) {
        Ok(key) => Ok(Ok(key)),
        Err(e) => {
            // 证据里只放有损展示形式，不影响判定。
            let shown = String::from_utf8_lossy(e.as_bytes()).into_owned();
            record(caller, func, shown, 0, CallResult::Invalid);
            Ok(Err(ERR_INVALID))
        }
    }
}

/// `get(key_ptr, key_len, out_ptr, out_cap) -> 值长度 | 负错误码`
pub fn host_get(
    mut caller: Caller<'_, TaskCtx>,
    key_ptr: i32,
    key_len: i32,
    out_ptr: i32,
    out_cap: i32,
) -> wasmtime::Result<i32> {
    let key = match read_key(&mut caller, "get", key_ptr, key_len)? {
        Ok(k) => k,
        Err(code) => return Ok(code),
    };

    if !allowed(&caller.data().read_prefixes, &key) {
        record(&mut caller, "get", key, 0, CallResult::Denied);
        return Ok(ERR_DENIED);
    }

    // 先读自己的暂存写入（read-your-writes），再读基准修订快照 ——
    // 与 scan 看到的是同一份已提交版本。
    let value = caller
        .data()
        .staged
        .get(&key)
        .or_else(|| caller.data().snapshot.get(&key))
        .cloned();

    let value = match value {
        Some(v) => v,
        None => {
            record(&mut caller, "get", key, 0, CallResult::NotFound);
            return Ok(ERR_NOT_FOUND);
        }
    };

    if out_cap < 0 || value.len() > out_cap as usize {
        record(
            &mut caller,
            "get",
            key,
            value.len(),
            CallResult::BufferTooSmall,
        );
        return Ok(ERR_BUF_TOO_SMALL);
    }

    // 写回 guest 内存前做边界检查。
    let oob = || OobError {
        func: "get",
        ptr: out_ptr,
        len: value.len() as i32,
    };
    if out_ptr < 0 {
        record(
            &mut caller,
            "get",
            key,
            value.len(),
            CallResult::OutOfBounds,
        );
        return Err(oob().into());
    }
    let mem = caller.data().memory.ok_or_else(oob)?;
    let start = out_ptr as usize;
    let end = start.checked_add(value.len()).ok_or_else(oob)?;
    if end > mem.data(&caller).len() {
        record(
            &mut caller,
            "get",
            key,
            value.len(),
            CallResult::OutOfBounds,
        );
        return Err(oob().into());
    }
    mem.write(&mut caller, start, &value).map_err(|_| oob())?;

    let n = value.len();
    record(&mut caller, "get", key, n, CallResult::Ok);
    Ok(n as i32)
}

/// `put(key_ptr, key_len, val_ptr, val_len) -> 0 | 负错误码`
pub fn host_put(
    mut caller: Caller<'_, TaskCtx>,
    key_ptr: i32,
    key_len: i32,
    val_ptr: i32,
    val_len: i32,
) -> wasmtime::Result<i32> {
    let key = match read_key(&mut caller, "put", key_ptr, key_len)? {
        Ok(k) => k,
        Err(code) => return Ok(code),
    };

    let value = match read_guest(&caller, "put", val_ptr, val_len) {
        Ok(v) => v,
        Err(e) => {
            record(&mut caller, "put", key, 0, CallResult::OutOfBounds);
            return Err(e.into());
        }
    };

    if !allowed(&caller.data().write_prefixes, &key) {
        record(&mut caller, "put", key, value.len(), CallResult::Denied);
        return Ok(ERR_DENIED);
    }

    let n = value.len();
    caller.data_mut().staged.insert(key.clone(), value);
    record(&mut caller, "put", key, n, CallResult::Ok);
    Ok(0)
}

/// `emit(tag_ptr, tag_len, data_ptr, data_len) -> 0 | 负错误码`
pub fn host_emit(
    mut caller: Caller<'_, TaskCtx>,
    tag_ptr: i32,
    tag_len: i32,
    data_ptr: i32,
    data_len: i32,
) -> wasmtime::Result<i32> {
    let tag_bytes = match read_guest(&caller, "emit", tag_ptr, tag_len) {
        Ok(b) => b,
        Err(e) => {
            record(&mut caller, "emit", String::new(), 0, CallResult::OutOfBounds);
            return Err(e.into());
        }
    };
    let tag = String::from_utf8_lossy(&tag_bytes).into_owned();

    let data = match read_guest(&caller, "emit", data_ptr, data_len) {
        Ok(d) => d,
        Err(e) => {
            record(&mut caller, "emit", tag, 0, CallResult::OutOfBounds);
            return Err(e.into());
        }
    };

    let would_exceed = {
        let ctx = caller.data();
        ctx.emitted_bytes + data.len() > ctx.max_output_bytes
    };
    if would_exceed {
        record(
            &mut caller,
            "emit",
            tag,
            data.len(),
            CallResult::OutputLimited,
        );
        return Ok(ERR_OUTPUT_LIMIT);
    }

    let n = data.len();
    let ctx = caller.data_mut();
    ctx.emitted_bytes += n;
    ctx.emitted.push((tag.clone(), data));
    record(&mut caller, "emit", tag, n, CallResult::Ok);
    Ok(0)
}

/// `scan(prefix_ptr, prefix_len, out_ptr, out_cap) -> 打包字节数 | 负错误码`
///
/// 视图 = 基准修订快照 ⊕ 本任务暂存写入（read-your-writes），再按读前缀
/// 逐键过滤 —— 与 `get` 的权限完全一致，不可读键的名字、值和条目长度
/// 都不会出现在输出里。每行依次为 u32 LE 键长度、键 UTF-8、u32 LE 值长度、
/// 值，按键的字节序排列。缓冲不足返回 -4 且一个字节都不写（不输出半行）。
pub fn host_scan(
    mut caller: Caller<'_, TaskCtx>,
    ptr: i32,
    len: i32,
    out: i32,
    cap: i32,
) -> wasmtime::Result<i32> {
    let prefix = match read_key(&mut caller, "scan", ptr, len)? {
        Ok(p) => p,
        Err(code) => return Ok(code),
    };

    // 先在一致性视图上打包全部行；此阶段不触碰 guest 内存，
    // 任何失败都不会写出半条记录。
    let bytes = {
        let ctx = caller.data();
        let mut merged: HashMap<&String, &Vec<u8>> = HashMap::new();
        for (k, v) in ctx.snapshot.iter().chain(ctx.staged.iter()) {
            if k.starts_with(prefix.as_str()) && allowed(&ctx.read_prefixes, k) {
                merged.insert(k, v);
            }
        }
        let mut rows: Vec<_> = merged.into_iter().collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        let mut bytes = Vec::new();
        for (k, v) in rows {
            bytes.extend_from_slice(&(k.len() as u32).to_le_bytes());
            bytes.extend_from_slice(k.as_bytes());
            bytes.extend_from_slice(&(v.len() as u32).to_le_bytes());
            bytes.extend_from_slice(v);
        }
        bytes
    };

    // 缓冲不足：返回 -4，一个字节都不写。
    if cap < 0 || bytes.len() > cap as usize {
        record(
            &mut caller,
            "scan",
            prefix,
            bytes.len(),
            CallResult::BufferTooSmall,
        );
        return Ok(ERR_BUF_TOO_SMALL);
    }

    // 写回前做显式边界检查；越界 → trap → 撤销全部暂存写入。
    let oob = || OobError {
        func: "scan",
        ptr: out,
        len: bytes.len() as i32,
    };
    let writable = out >= 0
        && (out as usize).checked_add(bytes.len()).is_some_and(|end| {
            caller
                .data()
                .memory
                .is_some_and(|m| end <= m.data(&caller).len())
        });
    if !writable {
        record(
            &mut caller,
            "scan",
            prefix,
            bytes.len(),
            CallResult::OutOfBounds,
        );
        return Err(oob().into());
    }
    let mem = caller.data().memory.ok_or_else(oob)?;
    mem.write(&mut caller, out as usize, &bytes)
        .map_err(|_| oob())?;

    let n = bytes.len();
    record(&mut caller, "scan", prefix, n, CallResult::Ok);
    Ok(n as i32)
}
