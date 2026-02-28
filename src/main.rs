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
    ifuncs: std::collections::HashSet<String>, // Símbols STT_GNU_IFUNC detectats al disc
    bias: Option<i64>, // None = no calibrat; Some(v) = calibrat (fins i tot si v==0)
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
        let mut ifuncs = std::collections::HashSet::new();

        // El bit VERSYM_HIDDEN marca símbols "hidden" (versions de compatibilitat,
        // ex: pthread_cond_signal@GLIBC_2.2.5). Els volem excloure i quedar-nos
        // només amb la versió per defecte (@@GLIBC_x.y.z).
        let versym_vec: Vec<goblin::elf::symver::Versym> = elf.versym
            .as_ref()
            .map(|v| v.iter().collect())
            .unwrap_or_default();

        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                // Saltem versions de compatibilitat (bit VERSYM_HIDDEN)
                if let Some(vs) = versym_vec.get(i) {
                    if vs.is_hidden() {
                        continue;
                    }
                }
                if sym.st_value != 0 {
                    offsets.insert(name.to_string(), sym.st_value);
                }
                // STT_GNU_IFUNC = 10
                if sym.st_type() == 10 {
                    ifuncs.insert(name.to_string());
                }
            }
        }

        Ok(LibCache {
            offsets,
            ifuncs,
            bias: None,
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
        // mem/str IFUNC de glibc
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
        // Allocadors de glibc (també resolts via IFUNC internament)
        "malloc",
        "free",
        "calloc",
        "realloc",
        "reallocarray",
        "memalign",
        "posix_memalign",
        "aligned_alloc",
        "valloc",
        "pvalloc",
        "malloc_usable_size",
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

    println!("[*] PID: {}, Base: 0x{:x}", pid, base_address);

    let mut global_cache: HashMap<String, LibCache> = HashMap::new();

    // Recopilem totes les ELFs a escanejar: el binari principal + totes les libs carregades
    // Cada element és (base_addr_en_ram, ruta_elf, got_names_propis)
    // Primer construïm la llista de libs úniques des dels maps
    let mut elfs_to_scan: Vec<(u64, String)> = Vec::new();

    // Binari principal
    elfs_to_scan.push((base_address, format!("/proc/{}/exe", pid)));

    // Llibreries compartides carregades
    let mut seen_libs = std::collections::HashSet::new();
    for map in &maps {
        if let procfs::process::MMapPath::Path(p) = &map.pathname {
            let path_str = p.display().to_string();
            // Ignorar el binari principal i entrades sense nom de lib
            if path_str.contains(&target_name) {
                continue;
            }
            // Només fitxers .so
            if !path_str.contains(".so") {
                continue;
            }
            if seen_libs.insert(path_str.clone()) {
                // La base de la lib és la primera mapeig executable (o el primer en general)
                let lib_base = maps
                    .iter()
                    .filter(|m| match &m.pathname {
                        procfs::process::MMapPath::Path(lp) => lp.display().to_string() == path_str,
                        _ => false,
                    })
                    .map(|m| m.address.0)
                    .min()
                    .unwrap_or(map.address.0);
                elfs_to_scan.push((lib_base, path_str));
            }
        }
    }

    println!("[*] ELFs a escanejar: {} (binari + {} libs)", elfs_to_scan.len(), elfs_to_scan.len() - 1);

    // Precomputem la base mínima de cada lib carregada.
    // Una .so pot tenir múltiples segments en memòria (codi r-xp + dades rw-p),
    // i el bias s'ha de calcular sempre des del mateix punt de referència.
    let mut lib_base_map: HashMap<String, u64> = HashMap::new();
    for map in &maps {
        if let procfs::process::MMapPath::Path(p) = &map.pathname {
            let path_str = p.display().to_string();
            let entry = lib_base_map.entry(path_str).or_insert(map.address.0);
            if map.address.0 < *entry {
                *entry = map.address.0;
            }
        }
    }

    for (elf_base, elf_path) in &elfs_to_scan {
        // Llegim el ELF des de disc (o /proc per al binari principal)
        let elf_buf = if elf_path.starts_with("/proc/") {
            fs::read(elf_path)
        } else {
            fs::read(elf_path).or_else(|_| {
                let proc_path = format!("/proc/{}/root{}", pid, elf_path);
                fs::read(&proc_path)
            })
        };

        let elf_buf = match elf_buf {
            Ok(b) => b,
            Err(_) => continue,
        };

        let cur_elf = match Elf::parse(&elf_buf) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Construïm dos mapes:
        // - plt_addrs: adreces de GOT corresponents a .rela.plt (SEMPRE funcions)
        // - cur_got_names: totes les entrades de relocalització (funcions + objectes)
        let mut cur_got_names: HashMap<u64, &str> = HashMap::new();
        let mut plt_addrs: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for rel in cur_elf.pltrelocs.iter() {
            if let Some(sym) = cur_elf.dynsyms.get(rel.r_sym) {
                if let Some(name) = cur_elf.dynstrtab.get_at(sym.st_name) {
                    let addr = elf_base + rel.r_offset;
                    cur_got_names.insert(addr, name);
                    plt_addrs.insert(addr);
                }
            }
        }
        for rel in cur_elf.dynrels.iter() {
            if let Some(sym) = cur_elf.dynsyms.get(rel.r_sym) {
                if let Some(name) = cur_elf.dynstrtab.get_at(sym.st_name) {
                    cur_got_names.insert(elf_base + rel.r_offset, name);
                }
            }
        }
        for rela in &cur_elf.dynrelas {
            if let Some(sym) = cur_elf.dynsyms.get(rela.r_sym) {
                if let Some(name) = cur_elf.dynstrtab.get_at(sym.st_name) {
                    cur_got_names.insert(elf_base + rela.r_offset, name);
                }
            }
        }

        if cur_got_names.is_empty() {
            continue;
        }

        // Trobar la secció GOT d'aquest ELF
        let got_section = cur_elf.section_headers.iter().find(|s| {
            let name = cur_elf.shdr_strtab.get_at(s.sh_name);
            name == Some(".got.plt") || name == Some(".got")
        });

        let got_section = match got_section {
            Some(s) => s,
            None => continue,
        };

        let start_addr = elf_base + got_section.sh_addr;

        if args.verbose {
            println!("[v] Escanejar GOT de {} a 0x{:x} ({} símbols)", elf_path, start_addr, cur_got_names.len());
        }

        for i in (0..got_section.sh_size).step_by(8) {
            let addr = start_addr + i;
            let mut buf = [0u8; 8];

            if handle.copy_address(addr as usize, &mut buf).is_ok() {
                let pointer = u64::from_le_bytes(buf);
                if pointer == 0 {
                    continue;
                }

                let sym_name = cur_got_names.get(&addr).copied().unwrap_or("???");
                if sym_name == "???" || sym_name.is_empty() {
                    continue;
                }

                let target_map = maps
                    .iter()
                    .find(|m| pointer >= m.address.0 && pointer <= m.address.1);

                // Cas crític: punter a memòria anònima (no mapejada per cap fitxer).
                // Això és el senyal més clar d'un backdoor injectat (shellcode).
                // Limitem al cas de PLT (funció): les variables GLOB_DAT de glibc
                // viuen legítimament en pàgines anònimes.
                let is_plt_func = plt_addrs.contains(&addr);
                if is_plt_func && target_map.map_or(true, |m| matches!(&m.pathname,
                    procfs::process::MMapPath::Anonymous | procfs::process::MMapPath::Heap | procfs::process::MMapPath::Stack
                )) {
                    println!("\x1b[0;1;31m[!!! SEGREST CRÍTIC !!!]\x1b[0m '{}' apunta a memòria anònima/heap/stack: 0x{:x}", sym_name, pointer);
                    println!("    GOT de: {}", elf_path);
                    continue;
                }

                if let Some(map) = target_map {
                    let lib_path = match &map.pathname {
                        procfs::process::MMapPath::Path(p) => p.display().to_string(),
                        procfs::process::MMapPath::Other(s) => s.clone(),
                        _ => continue,
                    };

                    // Usem la base mínima de la lib (no la del segment concret que conté el punter).
                    // Una lib pot tenir codi i dades en segments separats; el bias ha de ser
                    // relatiu al mateix punt de referència que st_value del ELF en disc.
                    let base_for_offset = lib_base_map
                        .get(&lib_path)
                        .copied()
                        .unwrap_or(map.address.0);
                    let offset_ram = (pointer - base_for_offset) as i64;

                    // --- LÒGICA D'AUTO-CALIBRATGE ---
                    if !global_cache.contains_key(&lib_path) {
                        if let Ok(c) = LibCache::new(&lib_path, pid) {
                            global_cache.insert(lib_path.clone(), c);
                            if args.verbose {
                                println!("[v] Nova llibreria detectada: {}", lib_path);
                            }
                        } else {
                            continue;
                        }
                    }

                    let cache = global_cache.get_mut(&lib_path).unwrap();

                    // Calibrem UNA SOLA VEGADA (bias == None). Usem Option per
                    // distingir "no calibrat" de "calibrat amb bias=0".
                    // No calibrem amb símbols IFUNC (ni de la llista manual ni detectats al disc).
                    let is_ifunc = ifunc_optimizations.contains(&sym_name)
                        || cache.ifuncs.contains(sym_name);

                    if cache.bias.is_none() && !is_ifunc {
                        if let Some(&off_disc) = cache.offsets.get(sym_name) {
                            let b = offset_ram - (off_disc as i64);
                            cache.bias = Some(b);
                            if args.verbose {
                                println!("[v] Calibratge fixat per {}: Bias 0x{:x} (usant {})",
                                    lib_path, b, sym_name);
                            }
                        }
                    }

                    let expected_ram = cache.bias.and_then(|b|
                        cache.offsets.get(sym_name).map(|&o| o as i64 + b)
                    );

                    match expected_ram {
                        Some(expected) if expected == offset_ram => {
                            if args.verbose { println!("\x1b[0;32m[OK]\x1b[0m {} (0x{:x})", sym_name, pointer); }
                        },
                        Some(expected) => {
                            if is_ifunc {
                                if args.verbose {
                                    println!("\x1b[0;36m[INFO]\x1b[0m {} (IFUNC optimitzat)", sym_name);
                                }
                            } else {
                                // Alerta real: la lib ja estava calibrada i l'offset no coincideix
                                println!("\x1b[0;31m[ALERTA INTEGRITAT]\x1b[0m Símbol '{}' manipulat!", sym_name);
                                println!("    GOT de: {}", elf_path);
                                println!("    Apunta a: {}", lib_path);
                                println!("    Esperat: 0x{:x}, Real: 0x{:x}", expected, offset_ram);
                            }
                        },
                        None => {
                            // expected_ram = None significa que el símbol NO és al cache de la lib.
                            // Pot ser: st_value=0, IFUNC amb resolució especial, o dades internes.
                            // Silenciem aquest cas: no tenim referència per jutjar.
                            // (El cas xz real produria ALERTA, no None, perquè el símbol SÍ és al cache.)
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
