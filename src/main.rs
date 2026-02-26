use anyhow::{Context, Result};
use goblin::elf::Elf;
// procfs provides Process type for working with /proc
use read_process_memory::{CopyAddress, ProcessHandle};
use std::convert::TryFrom;
use std::fs;

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
                let lib_name = path_to_string(&map.pathname);
                
                // AQUÍ ESTÀ LA LOGICA DE DETECCIÓ:
                // Si el punter apunta a liblzma però hauria d'anar a libcrypto...
                println!("  [GOT Entry] 0x{:x} -> apunta a: {}", addr, lib_name);
                
                if lib_name.contains("liblzma") {
                    println!("  \033[0;31m[ALERTA]\033[0m Punter sospitós detectat cap a xz/lzma!");
                }
            }
        }
    }

    Ok(())
}