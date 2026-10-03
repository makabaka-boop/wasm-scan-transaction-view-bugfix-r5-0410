//! 宿主函数与每任务执行上下文。
//!
//! 模块只能导入这里的 `get` / `put` / `emit` / `scan`。所有宿主函数：
//!  - 只访问当前调用者自己的 [`TaskCtx`]（该任务自己的上下文）；
//!  - 读取任务开始时基准修订的一致性快照，并叠加本任务的暂存写入，
//!    同一次执行内的点读与枚举始终对应同一已提交版本；
//!  - 对 guest 指针做严格的边界检查，越界即返回 [`OobError`]，
//!    wasmtime 会将其转为 trap，从而中止执行并撤销全部暂存写入；
//!  - 把每次调用的结果记录进证据列表，随运行报告返回。

use std::collections::{BTreeMap, HashMap};
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
    /// 输入编码非法（如 scan 前缀不是合法 UTF-8）。
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
    /// 任务开始时取下的基准修订一致性快照：本次执行的所有读取都对应它，
    /// 不受其他任务中途提交的影响。
    pub snapshot: BTreeMap<String, Vec<u8>>,
    /// 暂存写入：正常返回后才按基准修订号一次性提交。
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

/// `get(key_ptr, key_len, out_ptr, out_cap) -> 值长度 | 负错误码`
pub fn host_get(
    mut caller: Caller<'_, TaskCtx>,
    key_ptr: i32,
    key_len: i32,
    out_ptr: i32,
    out_cap: i32,
) -> wasmtime::Result<i32> {
    let key_bytes = read_guest(&caller, "get", key_ptr, key_len)?;
    let key = String::from_utf8_lossy(&key_bytes).into_owned();

    if !allowed(&caller.data().read_prefixes, &key) {
        record(&mut caller, "get", key, 0, CallResult::Denied);
        return Ok(ERR_DENIED);
    }

    // 先读自己的暂存写入（read-your-writes），再读基准快照 ——
    // 不读实时库，保证与本次执行的 scan 看到同一版本。
    let value = match caller.data().staged.get(&key) {
        Some(v) => Some(v.clone()),
        None => caller.data().snapshot.get(&key).cloned(),
    };

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
    let key_bytes = read_guest(&caller, "put", key_ptr, key_len)?;
    let key = String::from_utf8_lossy(&key_bytes).into_owned();

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
    let tag_bytes = read_guest(&caller, "emit", tag_ptr, tag_len)?;
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

/// `scan(prefix_ptr, prefix_len, out_ptr, out_cap) -> 打包行字节数 | 负错误码`
///
/// 二进制输出按键 UTF-8 字节排序，每行依次为 u32 LE 键长度、键、
/// u32 LE 值长度和值。语义与限制：
///  - 读取任务开始时的基准快照，并叠加本任务自己的暂存写入
///    （read-your-writes，同键时暂存优先）；
///  - 与 `get` 一致的逐键权限：无权读取的键整条丢弃，
///    键名、值以及二者的长度字段都不出现在输出里；
///  - 前缀不是合法 UTF-8 → `ERR_INVALID`，不写任何字节；
///  - 缓冲不足 → `ERR_BUF_TOO_SMALL`，同样一个字节都不写（没有半条记录）；
///  - 输出指针越界 → 记录证据并返回 [`OobError`]（→ trap → 撤销暂存写入）。
pub fn host_scan(
    mut caller: Caller<'_, TaskCtx>,
    ptr: i32,
    len: i32,
    out: i32,
    cap: i32,
) -> wasmtime::Result<i32> {
    let prefix_bytes = read_guest(&caller, "scan", ptr, len)?;
    let prefix = match std::str::from_utf8(&prefix_bytes) {
        Ok(p) => p.to_owned(),
        Err(_) => {
            let shown = String::from_utf8_lossy(&prefix_bytes).into_owned();
            record(&mut caller, "scan", shown, 0, CallResult::Invalid);
            return Ok(ERR_INVALID);
        }
    };

    let ctx = caller.data();
    // 合并基准快照与本任务的暂存写入；BTreeMap 直接给出键的字节序。
    let mut merged: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for (k, v) in &ctx.snapshot {
        if k.starts_with(&prefix) {
            merged.insert(k.as_str(), v.as_slice());
        }
    }
    for (k, v) in &ctx.staged {
        if k.starts_with(&prefix) {
            merged.insert(k.as_str(), v.as_slice());
        }
    }

    // 逐键权限过滤后序列化：不可读键连长度字段都不出现。
    let mut bytes = Vec::new();
    for (k, v) in merged {
        if !allowed(&ctx.read_prefixes, k) {
            continue;
        }
        bytes.extend_from_slice(&(k.len() as u32).to_le_bytes());
        bytes.extend_from_slice(k.as_bytes());
        bytes.extend_from_slice(&(v.len() as u32).to_le_bytes());
        bytes.extend_from_slice(v);
    }

    // 缓冲不足：返回 -4，不向 guest 内存写任何字节。
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

    // 写回 guest 内存前做边界检查（与 get 相同的严格程度）。
    let oob = || OobError {
        func: "scan",
        ptr: out,
        len: bytes.len() as i32,
    };
    if out < 0 {
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
    let start = out as usize;
    let end = start.checked_add(bytes.len()).ok_or_else(oob)?;
    if end > mem.data(&caller).len() {
        record(
            &mut caller,
            "scan",
            prefix,
            bytes.len(),
            CallResult::OutOfBounds,
        );
        return Err(oob().into());
    }
    mem.write(&mut caller, start, &bytes).map_err(|_| oob())?;

    let n = bytes.len();
    record(&mut caller, "scan", prefix, n, CallResult::Ok);
    Ok(n as i32)
}
