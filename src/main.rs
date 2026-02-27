use anyhow::{Context, Result};
use goblin::elf::Elf;
use read_process_memory::{CopyAddress, ProcessHandle};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;

struct LibCache {
    path: String,
    offsets: HashMap<String, u64>,
}

impl LibCache {
    fn new(path: &str) -> Result<Self> {
        let buffer = fs::read(path)?;
        let elf = Elf::parse(&buffer)?;
        let mut offsets = HashMap::new();

        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if sym.st_value != 0 {
                    offsets.insert(name.to_string(), sym.st_value);
                }
            }
        }
        Ok(LibCache {
            path: path.to_string(),
            offsets,
        })
    }

    // Aquesta és la versió integrada de library_exports_symbol
    fn exports(&self, symbol: &str) -> bool {
        self.offsets.contains_key(symbol)
    }
}

fn main() -> Result<()> {
    // Llista de símbols que solen causar falsos positius per optimitzacions (IFUNC)
    let ifunc_whitelist = [
        "strlen",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "strcmp",
        "strncmp",
        "strchr",
        "strrchr",
        "strcpy",
        "strcat",
        "strcspn",
        "strspn",
        "strpbrk",
        "__printf_chk",
        "__fprintf_chk",
        "__snprintf_chk",
        "__vsnprintf_chk",
        "abort",
        "raise",
        "fork",
        "getpid",
        "time",
    ];

    let target_name = "sshd";
    let all_procs = procfs::process::all_processes()?;
    let process = all_procs
        .into_iter()
        .filter_map(Result::ok)
        .find(|p| match p.stat() {
            Ok(stat) => stat.comm == target_name,
            Err(_) => false,
        })
        .context("No s'ha trobat el procés")?;

    let pid = process.pid;
    println!("[*] Analitzant {} (PID: {})", target_name, pid);

    let maps = process.maps()?;

    fn path_to_string(path: &procfs::process::MMapPath) -> String {
        match path {
            procfs::process::MMapPath::Path(p) => p.display().to_string(),
            procfs::process::MMapPath::Other(s) => s.clone(),
            _ => "unknown".to_string(),
        }
    }

    let base_address = maps
        .iter()
        .find(|m| path_to_string(&m.pathname).contains(target_name))
        .context("No s'ha trobat l'adreça base")?
        .address
        .0;

    let path = format!("/proc/{}/exe", pid);
    let buffer = fs::read(path)?;
    let elf = Elf::parse(&buffer)?;

    let mut got_names: HashMap<u64, &str> = HashMap::new();
    let mut global_cache: HashMap<String, LibCache> = HashMap::new();

    // Omplim noms de la GOT des de totes les taules de relocalització
    for rel in elf.pltrelocs.iter().chain(elf.dynrels.iter()) {
        if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                got_names.insert(base_address + rel.r_offset, name);
            }
        }
    }
    for rela in &elf.dynrelas {
        if let Some(sym) = elf.dynsyms.get(rela.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                got_names.insert(base_address + rela.r_offset, name);
            }
        }
    }

    let got_section = elf
        .section_headers
        .iter()
        .find(|s| {
            let name = elf.shdr_strtab.get_at(s.sh_name);
            name == Some(".got.plt") || name == Some(".got")
        })
        .context("No s'ha trobat la secció GOT")?;

    let got_address_in_ram = base_address + got_section.sh_addr;
    let handle = ProcessHandle::try_from(pid)?;

    println!("[+] Analitzant integritat de la GOT...");

    for i in (0..got_section.sh_size).step_by(8) {
        let addr = got_address_in_ram + i;
        let mut buf = [0u8; 8];

        if handle.copy_address(addr as usize, &mut buf).is_ok() {
            let pointer = u64::from_le_bytes(buf);
            if pointer == 0 {
                continue;
            }

            if let Some(map) = maps
                .iter()
                .find(|m| pointer >= m.address.0 && pointer <= m.address.1)
            {
                let lib_path = path_to_string(&map.pathname);
                let sym_name = got_names.get(&addr).copied().unwrap_or("???");

                if sym_name == "???" || !lib_path.starts_with("/") {
                    continue;
                }

                let lib_base_ram = map.address.0;
                let offset_real = pointer - lib_base_ram;

                let cache = global_cache.entry(lib_path.clone()).or_insert_with(|| {
                    LibCache::new(&lib_path).expect("Error carregant llibreria")
                });

                // --- VERIFICACIÓ D'INTEGRITAT UNIVERSAL ---

                if !cache.exports(sym_name) {
                    // CAS XZ: El punter va a una llibreria que NO té aquest símbol
                    println!("\x1b[0;31m[ALERTA SEGREST]\x1b[0m Símbol '{}' redirigit a llibreria aliena: {}", sym_name, lib_path);
                    if lib_path.contains("liblzma") {
                        println!("  -> Confirmada signatura de backdoor xz/lzma");
                    }
                } else if let Some(&offset_teoric) = cache.offsets.get(sym_name) {
                    // VERIFICACIÓ D'OFFSET: Està on hauria d'estar dins de la llibreria correcta?
                    if offset_real != offset_teoric {
                        let is_whitelisted = ifunc_whitelist.iter().any(|&s| s == sym_name);

                        if !is_whitelisted {
                            println!("\x1b[0;33m[AVÍS INTEGRITAT]\x1b[0m Símbol '{}' té offset anòmal a {}", sym_name, lib_path);
                            // ... la resta de printlns
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
