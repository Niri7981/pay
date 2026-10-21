//! macOS: Touch ID authentication + Apple Keychain storage.

use crate::{AuthGate, AuthIntent, Error, Result, SecretStore, Zeroizing};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const HELPER_SOURCE: &str = include_str!("helper.swift");
const CODESIGN: &str = "/usr/bin/codesign";
const SWIFTC: &str = "/usr/bin/swiftc";
const CDHASH_LEN: usize = 20;

const ENTITLEMENTS_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>"#;

// ── Touch ID auth gate ──────────────────────────────────────────────────────

pub struct TouchId;

impl AuthGate for TouchId {
    fn authenticate(&self, intent: &AuthIntent) -> Result<()> {
        let helper = trusted_helper()?;
        let message = intent.prompt_message();
        let output = run_helper(&helper, &["authenticate", &message], None)?;

        if output.status.success() {
            Ok(())
        } else {
            let err = extract_error(&output.stderr);
            if is_user_cancel(&err) {
                Err(Error::AuthDenied(err))
            } else {
                Err(Error::Backend(touch_id_unavailable_guidance(&err)))
            }
        }
    }

    fn is_available(&self) -> bool {
        trusted_helper()
            .and_then(|helper| run_helper(&helper, &["check-biometrics"], None))
            .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "yes")
            .unwrap_or(false)
    }
}

fn touch_id_unavailable_guidance(err: &str) -> String {
    format!(
        "{err}\n\nTouch ID is required to use macOS Keychain with pay. Make sure Touch ID is available and configured on this Mac, then try again."
    )
}

// ── Apple Keychain store ────────────────────────────────────────────────────

pub struct AppleKeychainStore;

impl SecretStore for AppleKeychainStore {
    fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        helper_store(key, data)
    }

    fn load(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let hex = Zeroizing::new(helper_run(&["read", key])?);
        crate::store::hex_decode(hex.trim()).map(Zeroizing::new)
    }

    fn exists(&self, key: &str) -> bool {
        helper_run(&["exists", key])
            .map(|out| out.trim() == "yes")
            .unwrap_or(false)
    }

    fn delete(&self, key: &str) -> Result<()> {
        helper_run(&["delete", key])?;
        Ok(())
    }
}

// ── Swift helper management ─────────────────────────────────────────────────
//
// The cached helper at `~/.cache/pay/pay.sh` is executable code that receives
// key material on stdin. Existing cache contents are only reused when they
// exactly match the signed helper embedded in this build and have private file
// metadata. Otherwise the helper is replaced atomically from trusted bytes or
// rebuilt from the embedded Swift source before it is executed.
//
// The pathname can still be swapped between validation and exec, so the
// helper is spawned suspended and only resumed once the kernel reports the
// code-directory hash of the validated bytes for the new process.

/// Pre-compiled Swift helper binary embedded at build time.
/// Empty if swiftc was not available during `cargo build`.
const EMBEDDED_HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pay-helper"));

struct TrustedHelper {
    path: PathBuf,
    cdhash: [u8; CDHASH_LEN],
}

fn trusted_helper() -> Result<TrustedHelper> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| Error::Backend("HOME is required for macOS Keychain helper".to_string()))?;
    let cache_dir = PathBuf::from(home).join(".cache").join("pay");
    let binary = cache_dir.join("pay.sh");
    let entitlements = cache_dir.join("pay.sh.entitlements");

    prepare_cache_dir(&cache_dir)?;
    if let Some(helper) = cached_helper(&binary)? {
        return Ok(helper);
    }

    install_helper(&cache_dir, &binary, &entitlements)?;
    let bytes = read_helper(&binary)?;
    if !EMBEDDED_HELPER.is_empty() && bytes != EMBEDDED_HELPER {
        return Err(Error::Backend(
            "Keychain helper changed during installation".to_string(),
        ));
    }
    Ok(TrustedHelper {
        cdhash: code_directory_hash(&bytes)?,
        path: binary,
    })
}

fn install_helper(cache_dir: &Path, binary: &Path, entitlements: &Path) -> Result<()> {
    if !EMBEDDED_HELPER.is_empty() {
        write_file_atomically(cache_dir, binary, EMBEDDED_HELPER, 0o700)?;
    } else {
        compile_helper_atomically(cache_dir, binary, entitlements)?;
    }

    validate_helper_file(binary)?;
    verify_codesign(binary)?;
    Ok(())
}

fn compile_helper_atomically(cache_dir: &Path, binary: &Path, entitlements: &Path) -> Result<()> {
    write_file_atomically(
        cache_dir,
        entitlements,
        ENTITLEMENTS_PLIST.as_bytes(),
        0o600,
    )?;

    let source = unused_temp_path(cache_dir, "pay.sh.swift")?;
    let tmp_binary = unused_temp_path(cache_dir, "pay.sh")?;

    let result = (|| {
        write_file_exclusive(&source, HELPER_SOURCE.as_bytes(), 0o600)?;

        let compile = Command::new(SWIFTC)
            .args(["-O", "-o"])
            .arg(&tmp_binary)
            .arg(&source)
            .output()
            .map_err(|e| {
                Error::Backend(format!(
                    "swiftc not found: {e}. Install Xcode Command Line Tools: xcode-select --install"
                ))
            })?;

        if !compile.status.success() {
            let stderr = String::from_utf8_lossy(&compile.stderr);
            return Err(Error::Backend(format!("swiftc failed: {stderr}")));
        }

        fs::set_permissions(&tmp_binary, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Backend(format!("Failed to set helper permissions: {e}")))?;
        codesign_binary(&tmp_binary, entitlements)?;
        fs::set_permissions(&tmp_binary, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Backend(format!("Failed to set helper permissions: {e}")))?;
        validate_helper_file(&tmp_binary)?;
        fs::rename(&tmp_binary, binary)
            .map_err(|e| Error::Backend(format!("Failed to install helper binary: {e}")))?;
        Ok(())
    })();

    fs::remove_file(&source).ok();
    if result.is_err() {
        fs::remove_file(&tmp_binary).ok();
    }
    result
}

fn prepare_cache_dir(cache_dir: &Path) -> Result<()> {
    match fs::symlink_metadata(cache_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(Error::Backend(format!(
                    "Refusing to use symlinked Keychain helper cache dir: {}",
                    cache_dir.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(Error::Backend(format!(
                    "Keychain helper cache path is not a directory: {}",
                    cache_dir.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(cache_dir)
                .map_err(|e| Error::Backend(format!("Failed to create cache dir: {e}")))?;
        }
        Err(e) => {
            return Err(Error::Backend(format!(
                "Failed to inspect Keychain helper cache dir: {e}"
            )));
        }
    }

    fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::Backend(format!("Failed to set cache dir permissions: {e}")))?;
    validate_cache_dir(cache_dir)
}

fn validate_cache_dir(cache_dir: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(cache_dir)
        .map_err(|e| Error::Backend(format!("Failed to inspect cache dir: {e}")))?;

    if metadata.file_type().is_symlink() {
        return Err(Error::Backend(format!(
            "Refusing to use symlinked Keychain helper cache dir: {}",
            cache_dir.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(Error::Backend(format!(
            "Keychain helper cache path is not a directory: {}",
            cache_dir.display()
        )));
    }
    if metadata.uid() != current_euid() {
        return Err(Error::Backend(format!(
            "Keychain helper cache dir is not owned by the current user: {}",
            cache_dir.display()
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(Error::Backend(format!(
            "Keychain helper cache dir has unsafe permissions: {}",
            cache_dir.display()
        )));
    }

    Ok(())
}

fn cached_helper(binary: &Path) -> Result<Option<TrustedHelper>> {
    match fs::symlink_metadata(binary) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Backend(format!(
                "Failed to inspect Keychain helper binary: {e}"
            )));
        }
    }

    if let Err(e) = validate_helper_file(binary) {
        remove_cached_helper(binary, &e.to_string())?;
        return Ok(None);
    }

    if EMBEDDED_HELPER.is_empty() || read_helper(binary)? != EMBEDDED_HELPER {
        remove_cached_helper(binary, "helper does not match embedded build artifact")?;
        return Ok(None);
    }

    verify_codesign(binary)?;
    Ok(Some(TrustedHelper {
        path: binary.to_path_buf(),
        cdhash: code_directory_hash(EMBEDDED_HELPER)?,
    }))
}

/// Reads the helper through a no-follow descriptor, validating its metadata
/// on that same descriptor.
fn read_helper(binary: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(binary)
        .map_err(|e| Error::Backend(format!("Failed to open helper binary: {e}")))?;
    let metadata = file
        .metadata()
        .map_err(|e| Error::Backend(format!("Failed to inspect helper binary: {e}")))?;
    validate_helper_metadata(&metadata, binary)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::Backend(format!("Failed to read helper binary: {e}")))?;
    Ok(bytes)
}

fn validate_helper_file(binary: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(binary)
        .map_err(|e| Error::Backend(format!("Failed to inspect helper binary: {e}")))?;
    validate_helper_metadata(&metadata, binary)
}

fn validate_helper_metadata(metadata: &fs::Metadata, binary: &Path) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(Error::Backend(format!(
            "Refusing to use symlinked Keychain helper binary: {}",
            binary.display()
        )));
    }
    if !metadata.is_file() {
        return Err(Error::Backend(format!(
            "Keychain helper path is not a regular file: {}",
            binary.display()
        )));
    }
    if metadata.uid() != current_euid() {
        return Err(Error::Backend(format!(
            "Keychain helper binary is not owned by the current user: {}",
            binary.display()
        )));
    }
    if metadata.nlink() != 1 {
        return Err(Error::Backend(format!(
            "Refusing to use hard-linked Keychain helper binary: {}",
            binary.display()
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(Error::Backend(format!(
            "Keychain helper binary has unsafe permissions: {}",
            binary.display()
        )));
    }

    Ok(())
}

fn remove_cached_helper(binary: &Path, reason: &str) -> Result<()> {
    fs::remove_file(binary).map_err(|e| {
        Error::Backend(format!(
            "Failed to remove untrusted Keychain helper binary ({reason}): {e}"
        ))
    })
}

fn write_file_atomically(
    cache_dir: &Path,
    destination: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
    let tmp = unused_temp_path(
        cache_dir,
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("pay"),
    )?;

    let result = (|| {
        write_file_exclusive(&tmp, contents, mode)?;
        fs::rename(&tmp, destination)
            .map_err(|e| Error::Backend(format!("Failed to install helper file: {e}")))?;
        Ok(())
    })();

    if result.is_err() {
        fs::remove_file(&tmp).ok();
    }
    result
}

fn write_file_exclusive(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| Error::Backend(format!("Failed to create helper file: {e}")))?;
    file.write_all(contents)
        .map_err(|e| Error::Backend(format!("Failed to write helper file: {e}")))?;
    file.sync_all()
        .map_err(|e| Error::Backend(format!("Failed to sync helper file: {e}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| Error::Backend(format!("Failed to set helper file permissions: {e}")))?;
    Ok(())
}

fn unused_temp_path(cache_dir: &Path, stem: &str) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    for attempt in 0..32 {
        let path = cache_dir.join(format!(
            ".{stem}.{}.{}.tmp",
            std::process::id(),
            nanos + attempt
        ));
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(path),
            Err(e) => {
                return Err(Error::Backend(format!(
                    "Failed to inspect helper temp path: {e}"
                )));
            }
            Ok(_) => {}
        }
    }
    Err(Error::Backend(
        "Failed to allocate a helper temp path".to_string(),
    ))
}

fn codesign_binary(binary: &Path, entitlements: &Path) -> Result<()> {
    let sign = Command::new(CODESIGN)
        .args(["-s", "-", "-f", "--options", "kill,hard", "--entitlements"])
        .arg(entitlements)
        .arg(binary)
        .output()
        .map_err(|e| Error::Backend(format!("codesign: {e}")))?;

    if !sign.status.success() {
        let stderr = String::from_utf8_lossy(&sign.stderr);
        return Err(Error::Backend(format!("codesign failed: {stderr}")));
    }
    Ok(())
}

fn verify_codesign(binary: &Path) -> Result<()> {
    let output = Command::new(CODESIGN)
        .args(["--verify", "--strict"])
        .arg(binary)
        .output()
        .map_err(|e| Error::Backend(format!("codesign verify: {e}")))?;

    if !output.status.success() {
        std::fs::remove_file(binary).ok();
        return Err(Error::Backend(
            "Keychain helper binary failed signature verification and was removed. \
             Please retry; it will be reinstalled."
                .to_string(),
        ));
    }
    Ok(())
}

// ── Identity-bound helper execution ────────────────────────────────────────

const CS_OPS_STATUS: u32 = 0;
const CS_OPS_CDHASH: u32 = 5;
const CS_VALID: u32 = 0x1;

unsafe extern "C" {
    fn csops(pid: libc::pid_t, ops: u32, useraddr: *mut libc::c_void, usersize: usize) -> i32;
}

/// Runs the helper only if the process the kernel actually started carries
/// the expected code-directory hash.
fn run_helper(helper: &TrustedHelper, args: &[&str], stdin: Option<&[u8]>) -> Result<Output> {
    run_verified(&helper.path, &helper.cdhash, args, stdin)
}

fn run_verified(
    program: &Path,
    expected_cdhash: &[u8; CDHASH_LEN],
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Output> {
    let spawn_err = |e: io::Error| Error::Backend(format!("pay.sh: {e}"));
    let (stdin_read, stdin_write) = cloexec_pipe().map_err(spawn_err)?;
    let (stdout_read, stdout_write) = cloexec_pipe().map_err(spawn_err)?;
    let (stderr_read, stderr_write) = cloexec_pipe().map_err(spawn_err)?;

    let program_c = c_string(program.as_os_str())?;
    let mut argv_owned = vec![program_c.clone()];
    for arg in args {
        argv_owned.push(c_string(OsStr::new(arg))?);
    }
    let envp_owned = std::env::vars_os()
        .map(|(key, value)| {
            let mut pair = key.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(value.as_bytes());
            CString::new(pair).map_err(|_| Error::Backend("environment contains NUL".to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut argv: Vec<*mut libc::c_char> =
        argv_owned.iter().map(|a| a.as_ptr() as *mut _).collect();
    argv.push(std::ptr::null_mut());
    let mut envp: Vec<*mut libc::c_char> =
        envp_owned.iter().map(|e| e.as_ptr() as *mut _).collect();
    envp.push(std::ptr::null_mut());

    let pid = spawn_suspended(
        &program_c,
        &argv,
        &envp,
        [&stdin_read, &stdout_write, &stderr_write],
    )
    .map_err(spawn_err)?;
    drop((stdin_read, stdout_write, stderr_write));

    if let Err(error) = verify_process_identity(pid, expected_cdhash) {
        // SAFETY: `pid` is our suspended, unreaped child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        wait_child(pid).ok();
        return Err(error);
    }
    // SAFETY: `pid` is our suspended, unreaped child.
    if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::kill(pid, libc::SIGKILL) };
        wait_child(pid).ok();
        return Err(spawn_err(error));
    }

    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        File::from(stderr_read).read_to_end(&mut buf).map(|_| buf)
    });
    let mut stdin_file = File::from(stdin_write);
    let write_result = match stdin {
        Some(input) => stdin_file.write_all(input),
        None => Ok(()),
    };
    drop(stdin_file);
    let mut stdout = Vec::new();
    let read_result = File::from(stdout_read).read_to_end(&mut stdout);
    let stderr = stderr_reader
        .join()
        .map_err(|_| Error::Backend("pay.sh: stderr reader panicked".to_string()))?;
    let status = wait_child(pid).map_err(spawn_err)?;

    write_result.map_err(|e| Error::Backend(format!("stdin write: {e}")))?;
    read_result.map_err(spawn_err)?;
    Ok(Output {
        status,
        stdout,
        stderr: stderr.map_err(spawn_err)?,
    })
}

fn verify_process_identity(pid: libc::pid_t, expected_cdhash: &[u8; CDHASH_LEN]) -> Result<()> {
    let mut cdhash = [0u8; CDHASH_LEN];
    let mut status = 0u32;
    // SAFETY: both buffers are valid for the sizes passed.
    let ok = unsafe {
        csops(pid, CS_OPS_CDHASH, cdhash.as_mut_ptr().cast(), cdhash.len()) == 0
            && csops(
                pid,
                CS_OPS_STATUS,
                (&mut status as *mut u32).cast(),
                std::mem::size_of::<u32>(),
            ) == 0
    };
    if !ok || status & CS_VALID == 0 || &cdhash != expected_cdhash {
        return Err(Error::Backend(
            "Keychain helper process does not match the validated helper; refusing to run it"
                .to_string(),
        ));
    }
    Ok(())
}

fn spawn_suspended(
    program: &CString,
    argv: &[*mut libc::c_char],
    envp: &[*mut libc::c_char],
    stdio: [&OwnedFd; 3],
) -> io::Result<libc::pid_t> {
    let check = |rc: libc::c_int| {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc))
        }
    };
    // SAFETY: the attr/file-action objects are initialised before use and
    // destroyed on every path; argv/envp are NUL-terminated arrays of
    // pointers into CStrings that outlive the call.
    unsafe {
        let mut attr: libc::posix_spawnattr_t = std::ptr::null_mut();
        check(libc::posix_spawnattr_init(&mut attr))?;
        let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        if let Err(e) = check(libc::posix_spawn_file_actions_init(&mut actions)) {
            libc::posix_spawnattr_destroy(&mut attr);
            return Err(e);
        }
        let result = (|| {
            check(libc::posix_spawnattr_setflags(
                &mut attr,
                (libc::POSIX_SPAWN_START_SUSPENDED | libc::POSIX_SPAWN_CLOEXEC_DEFAULT)
                    as libc::c_short,
            ))?;
            for (target, fd) in stdio.iter().enumerate() {
                check(libc::posix_spawn_file_actions_adddup2(
                    &mut actions,
                    fd.as_raw_fd(),
                    target as libc::c_int,
                ))?;
            }
            let mut pid: libc::pid_t = 0;
            check(libc::posix_spawn(
                &mut pid,
                program.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                envp.as_ptr(),
            ))?;
            Ok(pid)
        })();
        libc::posix_spawn_file_actions_destroy(&mut actions);
        libc::posix_spawnattr_destroy(&mut attr);
        result
    }
}

fn wait_child(pid: libc::pid_t) -> io::Result<ExitStatus> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out pointer.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
            return Ok(ExitStatus::from_raw(status));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe() writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe() just returned these descriptors and nothing else owns them.
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&pair.0, &pair.1] {
        // SAFETY: fd is a valid open descriptor.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(pair)
}

fn c_string(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| Error::Backend("helper argument contains NUL".to_string()))
}

/// Computes the cdhash the kernel reports for a thin 64-bit Mach-O: the
/// truncated SHA-256 of its strongest code directory.
fn code_directory_hash(binary: &[u8]) -> Result<[u8; CDHASH_LEN]> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const LC_CODE_SIGNATURE: u32 = 0x1d;
    const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
    const CSSLOT_CODEDIRECTORY: u32 = 0;
    const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
    const CS_HASHTYPE_SHA256: u8 = 2;

    let invalid = || Error::Backend("Keychain helper has no usable code signature".to_string());
    let le = |off: usize| -> Result<u32> {
        let bytes = binary
            .get(off..off.checked_add(4).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?))
    };
    let be = |base: &[u8], off: usize| -> Result<u32> {
        let bytes = base
            .get(off..off.checked_add(4).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| invalid())?))
    };

    if le(0)? != MH_MAGIC_64 {
        return Err(invalid());
    }
    let ncmds = le(16)? as usize;
    let mut offset = 32usize;
    let mut signature = None;
    for _ in 0..ncmds {
        let cmd = le(offset)?;
        let cmdsize = le(offset + 4)? as usize;
        if cmd == LC_CODE_SIGNATURE {
            let dataoff = le(offset + 8)? as usize;
            let datasize = le(offset + 12)? as usize;
            signature = binary.get(dataoff..dataoff.checked_add(datasize).ok_or_else(invalid)?);
            break;
        }
        if cmdsize < 8 {
            return Err(invalid());
        }
        offset = offset.checked_add(cmdsize).ok_or_else(invalid)?;
    }
    let signature = signature.ok_or_else(invalid)?;
    if be(signature, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(invalid());
    }

    let mut best: Option<(u8, &[u8])> = None;
    for index in 0..be(signature, 8)? as usize {
        let entry = 12 + index * 8;
        let slot = be(signature, entry)?;
        if slot != CSSLOT_CODEDIRECTORY
            && !(CSSLOT_ALTERNATE_CODEDIRECTORIES..CSSLOT_ALTERNATE_CODEDIRECTORIES + 5)
                .contains(&slot)
        {
            continue;
        }
        let start = be(signature, entry + 4)? as usize;
        let blob = signature.get(start..).ok_or_else(invalid)?;
        if be(blob, 0)? != CSMAGIC_CODEDIRECTORY {
            return Err(invalid());
        }
        let blob = blob.get(..be(blob, 4)? as usize).ok_or_else(invalid)?;
        let hash_type = *blob.get(37).ok_or_else(invalid)?;
        if best.is_none_or(|(current, _)| hash_rank(hash_type) > hash_rank(current)) {
            best = Some((hash_type, blob));
        }
    }

    match best {
        Some((CS_HASHTYPE_SHA256, blob)) => {
            let digest = Sha256::digest(blob);
            let mut cdhash = [0u8; CDHASH_LEN];
            cdhash.copy_from_slice(&digest[..CDHASH_LEN]);
            Ok(cdhash)
        }
        _ => Err(invalid()),
    }
}

/// Kernel preference order for code directories (higher wins).
fn hash_rank(hash_type: u8) -> u8 {
    match hash_type {
        1 => 1, // SHA-1
        3 => 2, // SHA-256 truncated
        2 => 3, // SHA-256
        4 => 4, // SHA-384
        _ => 0,
    }
}

fn current_euid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    // SAFETY: geteuid has no preconditions and does not write through pointers.
    unsafe { geteuid() }
}

fn helper_run(args: &[&str]) -> Result<String> {
    let helper = trusted_helper()?;
    let output = run_helper(&helper, args, None)?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let err = extract_error(&output.stderr);
        if is_user_cancel(&err) {
            Err(Error::AuthDenied(err))
        } else {
            Err(Error::Backend(err))
        }
    }
}

/// Detect Apple Keychain / LocalAuthentication "user cancelled" messages.
/// Covers our own "denied" sentinel, Touch ID cancel, and SecItemCopyMatching
/// cancel (errSecUserCanceled → "User canceled the operation.").
fn is_user_cancel(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m == "denied" || m.contains("cancel")
}

fn helper_store(key: &str, data: &[u8]) -> Result<()> {
    let hex = crate::store::hex_encode(data);
    let mut input = Zeroizing::new(Vec::with_capacity(hex.len() + 1));
    input.extend_from_slice(hex.as_bytes());
    input.push(b'\n');
    let helper = trusted_helper()?;
    let output = run_helper(&helper, &["store", key], Some(&input))?;

    if !output.status.success() {
        return Err(Error::Backend(extract_error(&output.stderr)));
    }
    Ok(())
}

fn extract_error(stderr: &[u8]) -> String {
    let s = String::from_utf8_lossy(stderr);
    s.lines()
        .find(|l| l.starts_with("ERROR:"))
        .map(|l| l.strip_prefix("ERROR:").unwrap_or("unknown").to_string())
        .unwrap_or_else(|| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct TestDir(PathBuf);

    impl TestDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).ok();
        }
    }

    fn test_dir(name: &str) -> TestDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "pay-keystore-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temp dir");
        TestDir(path)
    }

    #[test]
    fn validate_helper_file_accepts_private_regular_file() {
        let dir = test_dir("regular");
        let helper = dir.path().join("pay.sh");
        fs::write(&helper, b"helper").expect("write helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("set helper permissions");

        validate_helper_file(&helper).expect("private regular helper");
    }

    #[test]
    fn validate_helper_file_rejects_symlink() {
        let dir = test_dir("symlink");
        let target = dir.path().join("target");
        let helper = dir.path().join("pay.sh");
        fs::write(&target, b"helper").expect("write target");
        symlink(&target, &helper).expect("create symlink");

        let err = validate_helper_file(&helper).expect_err("symlink rejected");
        assert!(err.to_string().contains("symlinked"));
    }

    #[test]
    fn validate_helper_file_rejects_hard_link() {
        let dir = test_dir("hardlink");
        let helper = dir.path().join("pay.sh");
        let linked = dir.path().join("linked");
        fs::write(&helper, b"helper").expect("write helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("set helper permissions");
        fs::hard_link(&helper, &linked).expect("create hard link");

        let err = validate_helper_file(&helper).expect_err("hard link rejected");
        assert!(err.to_string().contains("hard-linked"));
    }

    #[test]
    fn cached_helper_discards_wrong_helper() {
        let dir = test_dir("wrong-helper");
        let helper = dir.path().join("pay.sh");
        fs::write(&helper, b"not the embedded helper").expect("write helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("set helper permissions");

        assert!(cached_helper(&helper).expect("helper check").is_none());
        assert!(!helper.exists());
    }

    #[test]
    fn validate_cache_dir_rejects_group_or_other_permissions() {
        let dir = test_dir("dir-perms");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770))
            .expect("set cache permissions");

        let err = validate_cache_dir(dir.path()).expect_err("unsafe directory rejected");
        assert!(err.to_string().contains("unsafe permissions"));
    }

    fn private_copy(dir: &TestDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, bytes).expect("write binary");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod binary");
        path
    }

    #[test]
    fn verified_spawn_runs_the_validated_helper() {
        if EMBEDDED_HELPER.is_empty() {
            return;
        }
        let dir = test_dir("verified-helper");
        let helper = private_copy(&dir, "pay.sh", EMBEDDED_HELPER);
        let cdhash = code_directory_hash(EMBEDDED_HELPER).expect("embedded helper cdhash");

        let output = run_verified(&helper, &cdhash, &["check-biometrics"], None)
            .expect("validated helper runs");
        assert!(output.status.success());
        let answer = String::from_utf8_lossy(&output.stdout);
        assert!(matches!(answer.trim(), "yes" | "no"), "{answer}");
    }

    #[test]
    fn verified_spawn_forwards_stdin_and_exit_status() {
        if EMBEDDED_HELPER.is_empty() {
            return;
        }
        let dir = test_dir("verified-stdin");
        let helper = private_copy(&dir, "pay.sh", EMBEDDED_HELPER);
        let cdhash = code_directory_hash(EMBEDDED_HELPER).expect("embedded helper cdhash");

        let output = run_verified(&helper, &cdhash, &["store", "acct"], Some(b"abc\n"))
            .expect("helper runs");
        assert!(!output.status.success(), "odd-length hex must be rejected");
        assert!(extract_error(&output.stderr).contains("odd length"));
    }

    #[test]
    fn verified_spawn_refuses_a_helper_swapped_after_validation() {
        if EMBEDDED_HELPER.is_empty() {
            return;
        }
        let dir = test_dir("swapped-helper");
        let marker = dir.path().join("ran");
        let validated = code_directory_hash(EMBEDDED_HELPER).expect("embedded helper cdhash");
        // Pathname now resolves to attacker code that would forge "OK".
        let substitute = private_copy(
            &dir,
            "pay.sh",
            format!("#!/bin/sh\ntouch '{}'\necho OK\n", marker.display()).as_bytes(),
        );

        let err = run_verified(&substitute, &validated, &["authenticate", "pay"], None)
            .expect_err("substituted helper rejected");
        assert!(err.to_string().contains("does not match"), "{err}");
        assert!(!marker.exists(), "substitute must never run");
    }

    #[test]
    fn verified_spawn_refuses_another_signed_binary() {
        if EMBEDDED_HELPER.is_empty() {
            return;
        }
        let validated = code_directory_hash(EMBEDDED_HELPER).expect("embedded helper cdhash");
        let err = run_verified(Path::new("/bin/echo"), &validated, &["OK"], None)
            .expect_err("different binary rejected");
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn code_directory_hash_rejects_unsigned_or_foreign_bytes() {
        assert!(code_directory_hash(b"#!/bin/sh\necho OK\n").is_err());
        assert!(code_directory_hash(&[]).is_err());
        let mut truncated = 0xfeed_facf_u32.to_le_bytes().to_vec();
        truncated.extend_from_slice(&[0; 12]);
        truncated.extend_from_slice(&1u32.to_le_bytes());
        assert!(code_directory_hash(&truncated).is_err());
    }

    #[test]
    fn read_helper_refuses_symlink() {
        let dir = test_dir("read-symlink");
        let target = private_copy(&dir, "target", b"helper");
        let helper = dir.path().join("pay.sh");
        symlink(&target, &helper).expect("create symlink");
        assert!(read_helper(&helper).is_err());
    }
}
