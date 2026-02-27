use anyhow::{Context, Result};
use goblin::elf::Elf;
// procfs provides Process type for working with /proc
use read_process_memory::{CopyAddress, ProcessHandle};
use std::convert::TryFrom;
use std::fs;
use std::collections::HashMap;

// Estructura per guardar els offsets d'una llibreria ja analitzada
struct LibCache {
    offsets: HashMap<String, u64>,
}

impl LibCache {
    fn new(path: &str) -> Result<Self> {
        let buffer = fs::read(path)?;
        let elf = Elf::parse(&buffer)?;
        let mut offsets = HashMap::new();

        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                // st_value en un .so és l'offset relatiu des de la base
                if sym.st_value != 0 {
                    offsets.insert(name.to_string(), sym.st_value);
                }
            }
        }
        Ok(LibCache { offsets })
    }
}


fn main() -> Result<()> {
    // 1. Busquem el procés víctima (ex: sshd)
    let target_name = "sshd";
    let all_procs = procfs::process::all_processes()?;
    // filter out any processes that failed to read, then look for the name
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

    // 2. Llegim el mapa de memòria per saber on estan les llibreries
    let maps = process.maps()?;
    
    // funció auxiliar per convertir un MMapPath a string
    fn path_to_string(path: &procfs::process::MMapPath) -> String {
        match path {
            procfs::process::MMapPath::Path(p) => p.display().to_string(),
            procfs::process::MMapPath::Other(s) => s.clone(),
            other => format!("{:?}", other),
        }
    }

    // Trobem l'adreça base on s'ha carregat el propi sshd
    let base_address = maps.iter()
        .find(|m| path_to_string(&m.pathname).contains(target_name))
        .context("No s'ha trobat l'adreça base de l'executable")?
        .address.0;

    // 3. Analitzem el binari al disc per trobar l'offset de la GOT
    let path = format!("/proc/{}/exe", pid);
    let buffer = fs::read(path)?;
    let elf = Elf::parse(&buffer)?;

    // 3b. Preparem un mapa per tenir el nom de cada símbol en una adreça de la GOT
    let mut got_names: HashMap<u64, &str> = HashMap::new();

    // mantenim una cache global de les biblioteques ja analitzades per evitar reiteracions
    let mut global_cache: HashMap<String, LibCache> = HashMap::new();

    // les relocalitzacions que afecten la PLT/GOT poden aparèixer en diverses llistes
    for rel in &elf.pltrelocs {
        if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let addr = base_address + rel.r_offset;
                got_names.insert(addr, name);
            }
        }
    }
    for rel in &elf.dynrels {
        if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let addr = base_address + rel.r_offset;
                got_names.insert(addr, name);
            }
        }
    }
    for rela in &elf.dynrelas {
        if let Some(sym) = elf.dynsyms.get(rela.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let addr = base_address + rela.r_offset;
                got_names.insert(addr, name);
            }
        }
    }

    // Busquem la secció .got.plt o la .got (per a binaris Full RELRO)
    let got_section = elf.section_headers.iter()
        .find(|s| {
            let name = elf.shdr_strtab.get_at(s.sh_name);
            name == Some(".got.plt") || name == Some(".got")
        })
        .context("No s'ha trobat cap secció GOT (.got o .got.plt). És possible que el binari estigui 'stripped' o usant un format no estàndard.")?;

    let got_address_in_ram = base_address + got_section.sh_addr;
    let got_size = got_section.sh_size;

    println!("[+] Secció {} trobada a 0x{:x}", 
        elf.shdr_strtab.get_at(got_section.sh_name).unwrap_or("?"), 
        got_address_in_ram);

    println!("[+] GOT trobada a la RAM: 0x{:x} (Mida: {} bytes)", got_address_in_ram, got_size);

    // 4. Llegim el contingut de la GOT de la memòria del procés
    // convertir PID a ProcessHandle segons la API de read-process-memory
    let handle = ProcessHandle::try_from(pid).context("No s'ha pogut obtenir el handle del procés")?;
    
    // Cada entrada de la GOT són 8 bytes (en 64-bit)
    for i in (0..got_size).step_by(8) {
        let addr = got_address_in_ram + i;
        let mut buf = [0u8; 8];
        // utilitzem el mètode del handle que escriu al buffer
        if handle.copy_address(addr as usize, &mut buf).is_ok() {
            let pointer = u64::from_le_bytes(buf);
            
            if pointer == 0 { continue; } // Ignorem entrades buides

            // 5. Verifiquem a quina llibreria pertany aquest punter
            if let Some(map) = maps.iter().find(|m| pointer >= m.address.0 && pointer <= m.address.1) {
                let lib_path = path_to_string(&map.pathname);
                let sym_name = got_names.get(&addr).copied().unwrap_or("???");

                if sym_name != "???" && lib_path.starts_with("/") {
                    // 1. Obtenim la base de la llibreria a la RAM (inici del mapping)
                    let lib_base_ram = map.address.0;
                    let offset_real = pointer - lib_base_ram;

                    // 2. Busquem l'offset teòric al fitxer del disc
                    let cache = global_cache.entry(lib_path.clone()).or_insert_with(|| {
                        LibCache::new(&lib_path).expect("Error analitzant llibreria")
                    });

                    if let Some(&offset_teoric) = cache.offsets.get(sym_name) {
                        if offset_real != offset_teoric {
                            println!(
                                "\033[0;31m[ALERTA CRÍTICA]\033[0m Símbol '{}' manipulat!", 
                                sym_name
                            );
                            println!("  Lloc: {}", lib_path);
                            println!("  Offset Disc: 0x{:x}", offset_teoric);
                            println!("  Offset RAM:  0x{:x}", offset_real);
                            println!("  Diferència:  {} bytes", (offset_real as i64 - offset_teoric as i64));
                        } else {
                            // println!("[OK] {} verificat", sym_name);
                        }
                    }
                }
            }
        }
    }

    // 1. Obtenim les dependències teòriques (DT_NEEDED) del binari al disc
let dependencies = &elf.libraries; 
println!("[*] Dependències declarades al disc: {:?}", dependencies);

// 2. Millorem el bucle de la GOT amb la "Prova de Coherència"
for i in (0..got_size).step_by(8) {
    let addr = got_address_in_ram + i;
    let mut buf = [0u8; 8];
    
    if handle.copy_address(addr as usize, &mut buf).is_ok() {
        let pointer = u64::from_le_bytes(buf);
        if pointer == 0 { continue; }

        if let Some(map) = maps.iter().find(|m| pointer >= m.address.0 && pointer <= m.address.1) {
            let lib_en_ram = path_to_string(&map.pathname);
            let sym_name = got_names.get(&addr).copied().unwrap_or("???");

            // Lògica de verificació:
            // Si el símbol és d'OpenSSL (per nom) però la llibreria no és libcrypto...
            let is_crypto_sym = sym_name.starts_with("RSA_") || sym_name.starts_with("EVP_");
            let points_to_crypto = lib_en_ram.contains("libcrypto");
            let points_to_lzma = lib_en_ram.contains("liblzma");

            if is_crypto_sym && !points_to_crypto {
                println!("  \033[0;31m[ALERTA CRÍTICA]\033[0m");
                println!("    Símbol: {}", sym_name);
                println!("    Esperat en: libcrypto.so");
                println!("    Trobat en:  {}", lib_en_ram);
            } else if points_to_lzma {
                // El cas específic de xz/liblzma
                println!("  \033[0;31m[BACKDOOR DETECTAT]\033[0m {} apunta a liblzma!", sym_name);
            } else {
                // Tot correcte
                // println!("  [OK] {} -> {}", sym_name, lib_en_ram);
            }
        }
    }
}

    Ok(())
}