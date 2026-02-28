use anyhow::{Context, Result};
use clap::Parser;
use goblin::elf::Elf;
use read_process_memory::{CopyAddress, ProcessHandle};
use std::collections::HashMap;
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about = "Auditor d'integritat de la GOT")]
struct Args {
    /// Nom del procés a analitzar (ex: sshd, nginx)
    #[arg(short, long)]
    target: String,

    /// Mostra informació detallada de cada símbol
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Ignora els símbols IFUNC optimitzats (recomanat)
    #[arg(short, long, default_value_t = true)]
    ignore_ifunc: bool,
}

struct LibCache {
    offsets: HashMap<String, u64>,
    bias: i64, // El desplaçament sistemàtic detectat
}

impl LibCache {
    fn new(path_str: &str, pid: i32) -> Result<Self> {
        // Intentem llegir el fitxer. Si falla, provem la ruta a través de /proc
        let buffer = fs::read(path_str).or_else(|_| {
            let proc_path = format!("/proc/{}/root{}", pid, path_str);
            fs::read(&proc_path)
        }).map_err(|e| {
            // Això ens dirà exactament quin fitxer no troba
            eprintln!("      \x1b[0;33m[!]\x1b[0m No es pot accedir a {} (Error: {})", path_str, e);
            e
        })?;

        let elf = Elf::parse(&buffer)?;
        let mut offsets = HashMap::new();

        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                // st_value és l'offset dins del fitxer .so
                if sym.st_value != 0 {
                    offsets.insert(name.to_string(), sym.st_value);
                }
            }
        }

        Ok(LibCache {
            offsets,
            bias: 0, // El calcularem dinàmicament amb el primer match
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let target_name = args.target;

    let all_procs = procfs::process::all_processes()?;
    let process = all_procs
        .into_iter()
        .filter_map(Result::ok)
        .find(|p| p.stat().map(|s| s.comm == target_name).unwrap_or(false))
        .context("No s'ha trobat el procés")?;

    let ifunc_optimizations = [
        "strlen",
        "memcpy",
        "memmove",
        "memset",
        "strcmp",
        "strncmp",
        "strchr",
        "strrchr",
        "strspn",
        "strcspn",
        "strpbrk",
        "strncasecmp",
        "strcasecmp",
        "memcmp",
        "__memcpy_chk",
        "__memset_chk",
        "__memmove_chk",
        "strnlen",
        "memchr",
    ];
    let pid = process.pid;
    let maps = process.maps()?;
    let handle = ProcessHandle::try_from(pid)?;

    // 1. Trobem l'executable i la seva base
    let base_address = maps
        .iter()
        .find(|m| match &m.pathname {
            procfs::process::MMapPath::Path(p) => p.to_string_lossy().contains(&target_name),
            procfs::process::MMapPath::Other(s) => s.contains(&target_name),
            _ => false,
        })
        .context("No s'ha trobat la base del binari a la RAM")?
        .address
        .0;

    let elf_buffer = fs::read(format!("/proc/{}/exe", pid))?;
    let elf = Elf::parse(&elf_buffer)?;
    let mut got_names = HashMap::new();

    // 2. Mapeig de noms (afegim log de quants noms trobem)
    for rel in elf.pltrelocs.iter().chain(elf.dynrels.iter()) {
        if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                got_names.insert(base_address + rel.r_offset, name);
            }
        }
    }
    // També per a binaris que usen RELA
    for rela in &elf.dynrelas {
        if let Some(sym) = elf.dynsyms.get(rela.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                got_names.insert(base_address + rela.r_offset, name);
            }
        }
    }

    println!("[*] PID: {}, Base: 0x{:x}", pid, base_address);
    println!(
        "[*] Símbols trobats a les taules de relocalització: {}",
        got_names.len()
    );

    // 3. Buscar la secció correcta
    let got_section = elf
        .section_headers
        .iter()
        .find(|s| {
            let name = elf.shdr_strtab.get_at(s.sh_name);
            name == Some(".got.plt") || name == Some(".got")
        })
        .context("No s'ha trobat secció .got ni .got.plt")?;

    let start_addr = base_address + got_section.sh_addr;
    println!(
        "[*] Analitzant GOT a 0x{:x} (Mida: {} bytes)",
        start_addr, got_section.sh_size
    );


    let mut global_cache: HashMap<String, LibCache> = HashMap::new();

    for i in (0..got_section.sh_size).step_by(8) {
        let addr = start_addr + i;
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
                let lib_path = match &map.pathname {
                    procfs::process::MMapPath::Path(p) => p.display().to_string(),
                    procfs::process::MMapPath::Other(s) => s.clone(),
                    _ => continue,
                };

                let sym_name = got_names.get(&addr).copied().unwrap_or("???");
                if sym_name == "???" {
                    continue;
                }

                let offset_ram = (pointer - map.address.0) as i64;

// --- LÒGICA D'AUTO-CALIBRATGE REFINADA (SENSE WARNINGS) ---
                if !global_cache.contains_key(&lib_path) {
                    if let Ok(c) = LibCache::new(&lib_path, pid) {
                        global_cache.insert(lib_path.clone(), c);
                        if args.verbose {
                            println!("[v] Nova llibreria detectada: {}", lib_path);
                        }
                    } else {
                    continue; // Si no podem llegir la llibreria, passem a la següent
                    }
                }

                let cache = global_cache.get_mut(&lib_path).unwrap();

                // Si el bias encara és 0 i el símbol actual NO és un IFUNC, calculem el bias real
                if cache.bias == 0 && !ifunc_optimizations.contains(&sym_name) {
                    if let Some(&off_disc) = cache.offsets.get(sym_name) {
                        cache.bias = offset_ram - (off_disc as i64);
                        if args.verbose { 
                            println!("[v] Calibratge fixat per {}: Bias 0x{:x} (usant {})", 
                                lib_path, cache.bias, sym_name); 
                        }
                    }
                }

                // Ara procedim a la verificació normal
                let expected_ram = cache.offsets.get(sym_name).map(|&o| o as i64 + cache.bias);
                
                match expected_ram {
                    Some(expected) if expected == offset_ram => {
                        if args.verbose { println!("\x1b[0;32m[OK]\x1b[0m {} (0x{:x})", sym_name, pointer); }
                    },
                    Some(expected) => {
                        if ifunc_optimizations.contains(&sym_name) {
                            if args.verbose { 
                                println!("\x1b[0;36m[INFO]\x1b[0m {} (IFUNC optimitzat)", sym_name); 
                            }
                        } else if cache.bias != 0 { 
                            // Només donem l'alerta si ja hem calibrat la llibreria
                            println!("\x1b[0;31m[ALERTA INTEGRITAT]\x1b[0m Símbol '{}' manipulat!", sym_name);
                            println!("    Llibreria: {}", lib_path);
                            println!("    Esperat: 0x{:x}, Real: 0x{:x}", expected, offset_ram);
                        }
                    },
                    None => {
                        println!("\x1b[0;1;31m[!!! SEGREST !!!]\x1b[0m '{}' apunta a zona externa: {}", sym_name, lib_path);
                    }
                }
            }
        }
    }
    Ok(())
}
