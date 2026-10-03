
插件可调用 env.scan 枚举可读键。二进制输出按键 UTF-8 字节排序，每行依次为 u32 LE 键长度、键、u32 LE 值长度和值。同次执行应读取输入基准修订中的数据并包含自己的暂存写入；scan 与 get 权限一致，禁止把不可读键的名字和长度暴露给插件。缓冲不足时返回 -4 且不写半行。前缀不是合法 UTF-8 时返回 -6；无论成功或失败，每次 scan 调用都会记入宿主调用证据。


Minimum build toolchain for the locked Wasmtime dependency: Rust 1.96.0; use `cargo +1.96.0 test --manifest-path plugin-host/Cargo.toml`.
