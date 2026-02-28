# got-auditor

Eina de seguretat en Rust per detectar manipulació de la **Global Offset Table (GOT)** en processos Linux en execució. Inspirada en la vulnerabilitat **CVE-2024-3094 (backdoor xz/liblzma)**, que va patchar el GOT de `sshd` per redirigir crides a `RSA_public_decrypt` cap a codi maliciós.

---

## Contingut

- [Motivació: el backdoor xz](#motivació-el-backdoor-xz)
- [Com funciona la GOT i per què és un vector d'atac](#com-funciona-la-got-i-per-què-és-un-vector-datac)
- [Funcionament de l'eina](#funcionament-de-leina)
- [Instal·lació i compilació](#installació-i-compilació)
- [Ús](#ús)
- [Interpretació de la sortida](#interpretació-de-la-sortida)
- [Deteccions implementades](#deteccions-implementades)
- [Limitacions conegudes](#limitacions-conegudes)
- [Detalls tècnics](#detalls-tècnics)

---

## Motivació: el backdoor xz

Al març de 2024, Andres Freund va descobrir que les versions 5.6.0 i 5.6.1 de **liblzma (xz-utils)** contenien un backdoor introduït per un actor maliciós sota el pseudònim "Jia Tan" durant quasi dos anys de contribucions aparentment legítimes.

El mecanisme tècnic era el següent:

1. `liblzma` s'inicialitzava via un constructor (`.init_array`) durant la càrrega del procés.
2. Aquest constructor usava `dlopen`/`dlsym` per trobar la funció `RSA_public_decrypt` dins `libcrypto.so`.
3. Patchejava l'entrada corresponent de la **GOT de `sshd`** per apuntar al codi maliciós en comptes de la implementació legítima d'OpenSSL.
4. Quan `sshd` intentava verificar claus públiques de clients, s'executava el backdoor.

La característica clau és que el backdoor **no modificava cap fitxer de disc** post-instal·lació: només modificava la memòria del procés en temps d'execució, fent-lo invisible a eines basades en hash de fitxers.

`got-auditor` detecta exactament aquest tipus de manipulació.

---

## Com funciona la GOT i per què és un vector d'atac

### La GOT en ELF

Els executables Linux compilats dinàmicament no coneixen en temps de compilació les adreces de les funcions de les llibreries (`libc`, `libssl`, etc.). En comptes, utilitzen dos mecanismes:

- **PLT (Procedure Linkage Table):** petits stubs de codi que fan un `JMP` indirecte.
- **GOT (Global Offset Table):** taula de punters en memòria a la que el PLT apunta.

Quan el programa crida `malloc()`, en realitat fa:
```
CALL malloc@PLT → JMP *GOT[malloc] → malloc en libc.so
```

El **dynamic linker (ld.so)** omple la GOT amb les adreces reals durant la càrrega del procés (o de forma lazy en la primera crida, depenent de la configuració).

### Per què és vulnerable

La GOT és una zona de memòria **escrivible** (`rw-p`). Qualsevol codi amb accés d'escriptura al procés (per exemple, un exploit de buffer overflow, un constructor maliciós d'una .so, o `ptrace`) pot modificar-ne les entrades per redirigir qualsevol crida a funció de llibreria cap a codi arbitrari, sense deixar rastre al disc.

Exemples d'atacs:
- **GOT overwrite via buffer overflow:** el payload sobreescriu una entrada de la GOT amb l'adreça del shellcode.
- **Constructor de .so maliciosa:** una llibreria carregada via `LD_PRELOAD` o dependència del sistema modifica el GOT d'un altre mòdul.
- **Backdoor de cadena de subministrament (com xz):** codi maliciós injectat en una llibreria legítima que modifica el GOT en memòria durant la inicialització.

---

## Funcionament de l'eina

`got-auditor` treballa exclusivament en memòria del procés en execució i fitxers del disc, sense necessitar instrumentació prèvia.

### Algorisme pas a pas

**1. Localització del procés**

Escaneja `/proc` per trobar el procés amb el nom indicat i obté el seu PID. Llegeix `/proc/PID/maps` per obtenir el mapa complet de memòria: quines zones estan mapejades, quins fitxers corresponen, i quina és l'adreça base de càrrega de cada mòdul.

**2. Enumeració de mòduls ELF**

Construeix una llista de tots els fitxers ELF actius en el procés:
- L'executable principal (via `/proc/PID/exe`)
- Totes les `.so` carregades (filtrades de `/proc/PID/maps`)

Per a cada mòdul, calcula la seva **base mínima de càrrega** — el mínim de totes les adreces del mapa que pertanyen a aquell fitxer. Això és essencial perquè una .so es mapeja en múltiples segments discontinus (codi `r-xp` + dades `rw-p`), i les adreces de les funcions al disc (`st_value`) es mesuren des del principi del fitxer, no des del segment de codi.

**3. Construcció del cache de símbols (`LibCache`)**

Per a cada .so que apareix com a destinació d'un punter GOT, `got-auditor` parseja el fitxer de disc corresponent amb `goblin`:

- Extreu la taula de símbols dinàmics (`dynsym`) amb les seves adreces en disc (`st_value`).
- Filtra les **versions de compatibilitat** de glibc usant la secció `.gnu.version` (`SHT_GNU_VERSYM`): les entrades amb el bit `VERSYM_HIDDEN` (0x8000) actiu corresponen a versions antigues (ex: `pthread_cond_signal@GLIBC_2.2.5`) que s'exclouen per quedar-nos amb la versió per defecte (`@@GLIBC_2.3.2`).
- Detecta automàticament **símbols IFUNC** (`STT_GNU_IFUNC`, tipus 10): funcions que el linker resol a variants optimitzades per a l'arquitectura (ex: `memcpy` → versió AVX-512 en x86_64). Aquests símbols s'exclouen de la verificació perquè apunten legítimament a adreces que no es poden predir des del fitxer de disc.

**4. Auto-calibratge del bias ASLR**

Linux carrega les .so en adreces aleatòries (ASLR). L'eina no coneix a priori on s'ha carregat cada mòdul. En comptes, **dedueix el bias de reubicació** observant el primer símbol verificable:

```
bias = offset_en_ram - st_value_en_disc
```

**Propietats clau del calibratge:**
- Es realitza **una sola vegada** per mòdul, usant `Option<i64>` per distingir "no calibrat" (`None`) de "bias calculat, fins i tot si és zero" (`Some(0)`). Calibrar repetidament sobreescriuria el valor correcte.
- S'exclouen IFUNCs i la llista de símbols especials del calibratge.
- Si el calibratge inicial usa un símbol ja manipulat (atac sofisticat), el bias seria erroni → limitació documentada a la secció de limitacions.

**5. Verificació de cada entrada GOT**

Per a cada adreça de la GOT (`start + offset`, en 8 bytes):

1. Llegeix el punter de la memòria del procés via `process_vm_readv`.
2. Busca a quin segment del mapa pertany el punter.
3. **Detecció de memòria anònima:** si el punter apunta a memòria anònima/heap/stack (no a cap fitxer `.so`) i l'entrada prové de la PLT (és una funció, no una variable global), dispara `SEGREST CRÍTIC`.
4. Calcula `offset_real = pointer - base_minima_lib`.
5. Compara amb `offset_esperat = st_value + bias`.
6. Si no coincideixen i no és un IFUNC → `ALERTA INTEGRITAT`.

---

## Instal·lació i compilació

### Prerequisits

- **Rust** (edició 2021 o posterior): https://rustup.rs
- **Linux** (requereix `/proc`)
- Permisos de **root** o `CAP_SYS_PTRACE` per llegir la memòria d'altres processos

### Compilació

```bash
git clone <repo>
cd got-auditor
cargo build --release
```

El binari resultant es troba a `target/release/got_auditor`.

Per a propòsits de depuració:
```bash
cargo build   # debug, amb símbols
```

### Dependències (Cargo.toml)

| Crate | Versió | Ús |
|-------|--------|----|
| `goblin` | 0.8 | Parseig d'ELF: símbols, relocs, versym, seccions |
| `procfs` | 0.16 | Lectura de `/proc/PID/maps`, llista de processos |
| `read-process-memory` | 0.1 | Lectura de memòria del procés via `process_vm_readv` |
| `anyhow` | 1.0 | Gestió d'errors ergonòmica |
| `clap` | 4.3 | Parseig d'arguments CLI |

---

## Ús

```
got_auditor [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>       Nom del procés a analitzar (ex: sshd, nginx)
  -v, --verbose               Mostra informació detallada de cada símbol
  -i, --ignore-ifunc          Ignora els símbols IFUNC optimitzats (recomanat) [default: true]
  -h, --help                  Mostra l'ajuda
  -V, --version               Mostra la versió
```

### Exemples

**Anàlisi simple (mode silenciós, només alerta d'anomalies):**
```bash
sudo ./got_auditor -t sshd
```

**Anàlisi verbose (veu cada símbol verificat):**
```bash
sudo ./got_auditor -t sshd -v
```

**Redirigir la sortida a fitxer:**
```bash
sudo ./got_auditor -t nginx -v > informe_nginx.txt 2>&1
```

**Filtrar per funcions de criptografia:**
```bash
sudo ./got_auditor -t sshd -v | grep -iE "crypt|rsa|evp|aes"
```

**Executar periòdicament per monitorització contínua:**
```bash
watch -n 30 'sudo ./got_auditor -t sshd 2>&1 | grep -v "^\[\*\]"'
```

### Nota sobre permisos

L'eina necessita llegir la memòria del procés objectiu, cosa que requereix:
- Executar com a **root** (`sudo`), o
- Tenir la capability `CAP_SYS_PTRACE`, o
- Que el procés objectiu sigui del mateix usuari i `ptrace_scope` ho permeti.

En sistemes amb `kernel.yama.ptrace_scope = 1` (per defecte en moltes distros), cal root.

---

## Interpretació de la sortida

### Format de sortida

```
[*] PID: 12345, Base: 0x55a3c4000000
[*] ELFs a escanejar: 6 (binari + 5 libs)
```
Informació general: PID trobat, adreça base del binari, i quants mòduls s'analitzaran.

---

```
[v] Nova llibreria detectada: /usr/lib/libcrypto.so.3
[v] Calibratge fixat per /usr/lib/libcrypto.so.3: Bias 0x0 (usant RSA_set0_key)
[v] Escanejar GOT de /usr/lib/libcrypto.so.3 a 0x7f... (160 símbols)
```
*(Només en mode `-v`)* Informació de diagnòstic: una nova llibreria s'ha descobert, el bias ASLR calculat, i quants símbols conté la GOT d'aquell mòdul.

---

```
[OK] EVP_DigestSign (0x7f9a3b4d240)
```
*(Només en mode `-v`)* El símbol `EVP_DigestSign` a la GOT apunta a l'adreça esperada dins `libcrypto.so`. Tot correcte.

---

```
[INFO] memcpy (IFUNC optimitzat)
```
*(Només en mode `-v`)* El símbol és un IFUNC. Es resolt a una variant específica per arquitectura i no es pot verificar matemàticament. S'ignora.

---

```
[ALERTA INTEGRITAT] Símbol 'RSA_public_decrypt' manipulat!
    GOT de: /usr/lib/libssl.so.3
    Apunta a: /usr/lib/libcrypto.so.3
    Esperat: 0x3a4b20, Real: 0x1f2e80
```
**Anomalia detectada.** El punter GOT del símbol `RSA_public_decrypt` a la taula de `libssl.so` apunta a un offset de `libcrypto.so` diferent del que hauria d'apuntar. Pot indicar un backdoor (com el cas xz), un error de versió de llibreria incompatible, o, en rars casos, un optimitzador no documentat.

---

```
[!!! SEGREST CRÍTIC !!!] 'RSA_public_decrypt' apunta a memòria anònima/heap/stack: 0x7f9a00001234
    GOT de: /usr/lib/libssl.so.3
```
**Cas extrem d'atac.** El punter GOT d'una funció no apunta a cap fitxer .so carregat, sinó a memòria anònima. Amb tota probabilitat conté shellcode injectat.

---

## Deteccions implementades

| Tipus d'atac | Detectat? | Mecanisme |
|---|---|---|
| **Backdoor estil xz** (GOT patch en .so) | ✅ Sí | `ALERTA INTEGRITAT`: offset no coincideix |
| **GOT overwrite via buffer overflow** | ✅ Sí | `ALERTA INTEGRITAT` o `SEGREST CRÍTIC` |
| **Shellcode en memòria anònima** | ✅ Sí | `SEGREST CRÍTIC`: punter a mmap anònim |
| **Redirecció a funció diferent dins la mateixa .so** | ✅ Sí | `ALERTA INTEGRITAT`: offset diferent |
| **Redirecció a una .so completament diferent** | ✅ Sí | `ALERTA INTEGRITAT`: lib inesperada al cache |
| **Punters a stack o heap** | ✅ Sí (PLT) | `SEGREST CRÍTIC` |

---

## Limitacions conegudes

### No detecta

**1. Inline hooks (patcheig del cos de la funció)**

Si un atacant patcheja els primers bytes de la funció (ex: insereix un `JMP addr_maliciosa`), el punter GOT continua essent correcte. L'eina verificaria `[OK]`, però el codi seria maliciós. Per detectar-ho caldria comparar el contingut de les pàgines de codi amb els hash del fitxer de disc — a eines com `rkhunter`.

**2. `LD_PRELOAD` i `LD_AUDIT`**

Si una .so maliciosa es carrega com a preload, el dynamic linker resol les crides cap a ella legítimament. Des del punt de vista de la GOT, el punter apunta a la .so del preload amb un bias correcte → `[OK]`. L'eina no pot distingir una .so legítima d'una maliciosa per nom o ubicació.

**3. Rootkits que modifiquen disc i memòria simultàniament**

`got-auditor` compara la memòria del procés contra el fitxer de disc. Si un rootkit altera tant el procés com el fitxer corresponent, la diferència és zero i no es detectaria res.

**4. Calibratge enverinat ("first-symbol attack")**

Si el primer símbol que l'eina usa per calibrar el bias d'una .so **ja té el GOT manipulat**, el bias calculat absorbiria el desplaçament de l'atac, i tots els símbols posteriors d'aquella .so semblarien correctes. Un atacant sofisticat podria explotar això manipulant només els símbols posteriors i deixant el primer intacte.

*Mitigació possible (no implementada):* calibrar amb múltiples símbols i alertar si hi ha inconsistències entre ells.

**5. Modificació del dynamic linker (`ld.so`)**

`ld.so` és el responsable de carregar les .so i omplir la GOT. Un atac que comprometés `ld.so` podria fer que tots els valors de la GOT fossin "correctes" des del punt de vista de l'eina però apuntessin a codi maliciós.

**6. Processos curts i JIT**

Processos que creen codi en temps d'execució (JVM, V8, LuaJIT, etc.) o que es reinicien ràpidament poden generar falsos positius o impedir l'anàlisi.

---

## Detalls tècnics

### Per quin motiu s'analitzen les .so i no només el binari principal?

El backdoor xz no modificava el GOT de `sshd` directament, sinó el GOT de `libssl.so`. `sshd` crida `libssl`, que internament crida `libcrypto`. La funció `RSA_public_decrypt` no apareix al GOT de `sshd` perquè `sshd` no la usa directament. Una eina que només analitzi el binari principal perdria completament aquest vector d'atac.

### Per qué `Option<i64>` per al bias?

El bias ASLR d'un mòdul pot ser zero legítimament (ex: un executable compilat sense PIE, o per coincidència de càrrega). Si usem `i64` amb `0` com a valor sentinella per a "no calibrat", recalibrarem en cada símbol, sobreescrivint el bias correcte i generant falsos positius. `Option<i64>` permet distingir inequívocament `None` (no calibrat) de `Some(0)` (calibrat, bias és zero).

### Símbols versionats de glibc

glibc exposa múltiples versions del mateix símbol per a compatibilitat binària:
- `pthread_cond_signal@GLIBC_2.2.5` → offset `0x94580` (versió antiga, ABI antiga)
- `pthread_cond_signal@@GLIBC_2.3.2` → offset `0x95820` (versió per defecte)

Si el `LibCache` guarda la versió antiga però la lib que es verifica usa la versió per defecte, l'offset esperit seria erroni i generaria un fals positiu. L'eina filtra les entrades amb `Versym::is_hidden()` (bit `VERSYM_HIDDEN = 0x8000`) per quedar-se únicament amb les versions per defecte (`@@`).

### GOT PLT vs GOT GLOB_DAT

Les entrades de la GOT es divideixen en dos grups:
- **`.rela.plt`:** relocalizaciones de funcions. El punter ha d'apuntar a una funció de codi en una .so.
- **`.rela.dyn` (GLOB_DAT, COPY, etc.):** variables globals exportades. Per exemple, `optarg` o `stdout` de glibc viuen en pàgines de dades anònimes (COW, copy-on-write) i no en el segment de fitxer de la .so.

La detecció de "memòria anònima sospitosa" s'aplica **només a entrades PLT** per evitar falsos positius amb variables globals legítimes.

### Eficiència

L'eina parseja cada fitxer .so **una sola vegada** per procés i guarda els resultats en `HashMap` (cache). Les execucions posteriors del bucle de verificació no rellegeixen el disc. La complexitat és O(N · M) on N = entrades GOT totals i M = entrades al cache, però en pràctica M és constant i petit.
