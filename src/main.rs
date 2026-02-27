use anyhow::{Context, Result};
use goblin::elf::Elf;
use read_process_memory::{CopyAddress, ProcessHandle};
use std::collections::HashMap;
use std::fs;

// Mode Verbose: Pots canviar-ho a true o fer que sigui un argument
const VERBOSE: bool = false;

struct LibCache {
    offsets: HashMap<String, u64>,
    bias: i64, // El desplaçament sistemàtic detectat
}

impl LibCache {
    fn new(path: &str, first_symbol_offset: Option<i64>) -> Result<Self> {
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
            offsets, 
            bias: first_symbol_offset.unwrap_or(0) 
        })
    }
}

fn main() -> Result<()> {
    let target_name = "sshd";

    let ifunc_optimizations = [
        "strlen", "memcpy", "memmove", "memset", "strcmp", "strncmp", 
        "strchr", "strrchr", "strspn", "strcspn", "strpbrk", "strncasecmp", 
        "strcasecmp", "memcmp", "__memcpy_chk", "__memset_chk", "__memmove_chk",
        "strnlen", "memchr"
    ];
    let all_procs = procfs::process::all_processes()?;
    let process = all_procs.into_iter().filter_map(Result::ok)
        .find(|p| p.stat().map(|s| s.comm == target_name).unwrap_or(false))
        .context("No s'ha trobat el procés")?;
    
    let pid = process.pid;
    let maps = process.maps()?;
    let handle = ProcessHandle::try_from(pid)?;

    // 1. Trobem l'executable i la seva base
    let base_address = maps.iter()
        .find(|m| match &m.pathname {
            procfs::process::MMapPath::Path(p) => p.to_string_lossy().contains(target_name),
            procfs::process::MMapPath::Other(s) => s.contains(target_name),
            _ => false,
        })
        .context("No s'ha trobat la base del binari a la RAM")?.address.0;

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
    println!("[*] Símbols trobats a les taules de relocalització: {}", got_names.len());

    // 3. Buscar la secció correcta
    let got_section = elf.section_headers.iter()
        .find(|s| {
            let name = elf.shdr_strtab.get_at(s.sh_name);
            name == Some(".got.plt") || name == Some(".got")
        })
        .context("No s'ha trobat secció .got ni .got.plt")?;

    let start_addr = base_address + got_section.sh_addr;
    println!("[*] Analitzant GOT a 0x{:x} (Mida: {} bytes)", start_addr, got_section.sh_size);

    let mut global_cache: HashMap<String, LibCache> = HashMap::new();

    // 4. Bucle principal
    for i in (0..got_section.sh_size).step_by(8) {
        let addr = start_addr + i;
        let mut buf = [0u8; 8];
        
        if handle.copy_address(addr as usize, &mut buf).is_ok() {
            let pointer = u64::from_le_bytes(buf);
            if pointer == 0 { continue; }

            // Busquem el mapa de memòria on cau el punter
            if let Some(map) = maps.iter().find(|m| pointer >= m.address.0 && pointer <= m.address.1) {
                let lib_path = match &map.pathname {
                    procfs::process::MMapPath::Path(p) => p.display().to_string(),
                    procfs::process::MMapPath::Other(s) => s.clone(),
                    _ => continue,
                };

                let sym_name = got_names.get(&addr).copied().unwrap_or("???");
                
                // Si el símbol no té nom, mirem si és un punter intern
                if sym_name == "???" {
                    if VERBOSE { println!("[?] Punter anònim a 0x{:x} -> {}", addr, lib_path); }
                    continue;
                }

                let offset_ram = (pointer - map.address.0) as i64;

                // Calculem el cache i el BIAS
                let cache = global_cache.entry(lib_path.clone()).or_insert_with(|| {
                    let temp = LibCache::new(&lib_path, None).expect("Error disc");
                    let bias = if let Some(&off_disc) = temp.offsets.get(sym_name) {
                        offset_ram - (off_disc as i64)
                    } else { 0 };
                    if VERBOSE { println!("[v] Llibreria carregada: {} (Bias: 0x{:x})", lib_path, bias); }
                    LibCache { bias, ..temp }
                });

                let expected_ram = cache.offsets.get(sym_name).map(|&o| o as i64 + cache.bias);
                
                match expected_ram {
                    Some(expected) if expected == offset_ram => {
                        if VERBOSE { println!("\x1b[0;32m[OK]\x1b[0m {} (0x{:x})", sym_name, pointer); }
                    },
                    Some(_) => {
                        if ifunc_optimizations.contains(&sym_name) {
                            if VERBOSE { println!("\x1b[0;36m[IFUNC]\x1b[0m {} optimitzat per CPU (0x{:x})", sym_name, pointer); }
                        } else {
                            println!("\x1b[0;31m[ALERTA REAL]\x1b[0m {} manipulat! Offset anòmal: 0x{:x}", sym_name, offset_ram);
                        }
                    },
                    None => {
                        // Aquest és el cas més perillós: el símbol apunta a una llibreria que no és la seva
                        println!("\x1b[0;1;31m[!!! SEGREST DETECTAT !!!]\x1b[0m");
                        println!("    El símbol '{}' hauria d'estar a la llibreria original,", sym_name);
                        println!("    però apunta a: {}", lib_path);
                    }
                }
            }
        }
    }
    Ok(())
}