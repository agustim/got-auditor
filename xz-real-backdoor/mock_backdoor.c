/*
 * mock_backdoor.c - Simulació fidel del mecanisme de CVE-2024-3094
 *
 * El backdoor real de liblzma 5.6.1 fa exactament això en el seu constructor:
 *   1. Cerca RSA_public_decrypt a la memòria del procés via dl_iterate_phdr
 *   2. Sobreescriu els primers bytes amb un JMP a codi maliciós
 *
 * Aquí reproduïm els passos 1 i 2 però amb NOPs benignes (0x90) en lloc
 * del JMP maliciós, per demostrar que got-auditor detecta el patching.
 *
 * Compilar:
 *   gcc -shared -fPIC -o mock_backdoor.so mock_backdoor.c -ldl
 *
 * Usar:
 *   sudo LD_PRELOAD=/got-auditor/xz-real-backdoor/mock_backdoor.so \
 *        /usr/sbin/sshd -D -p 2222 &
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

/* Nombre del símbol que el backdoor real hooketja */
#define TARGET_SYM "RSA_public_decrypt"

/*
 * Els 4 bytes que escrivim: NOP sled 0x90909090
 * El backdoor real escrivia: 0xE9 <offset_32bit> (JMP rel32)
 * Usem NOPs per ser benignes però l'efecte sobre RAM vs disc és idèntic.
 */
static const uint8_t PATCH_BYTES[4] = {0x90, 0x90, 0x90, 0x90};

static void patch_symbol(void) {
    /* Cerquem RSA_public_decrypt via dlsym (igual que el backdoor real) */
    void *libcrypto = dlopen("libcrypto.so.3", RTLD_NOLOAD | RTLD_NOW);
    if (!libcrypto) {
        libcrypto = dlopen("libcrypto.so.1.1", RTLD_NOLOAD | RTLD_NOW);
    }
    if (!libcrypto) {
        fprintf(stderr, "[mock_backdoor] No s'ha trobat libcrypto\n");
        return;
    }

    void *target = dlsym(libcrypto, TARGET_SYM);
    if (!target) {
        fprintf(stderr, "[mock_backdoor] No s'ha trobat %s\n", TARGET_SYM);
        dlclose(libcrypto);
        return;
    }

    fprintf(stderr, "[mock_backdoor] %s trobat a %p\n", TARGET_SYM, target);
    fprintf(stderr, "[mock_backdoor] Primers bytes originals: ");
    for (int i = 0; i < 8; i++) {
        fprintf(stderr, "%02x ", ((uint8_t*)target)[i]);
    }
    fprintf(stderr, "\n");

    /*
     * Fem la pàgina writable temporalment (mprotect),
     * exactament com fa el backdoor real.
     */
    uintptr_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target;
    uintptr_t page_start = addr & ~(page_size - 1);

    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("[mock_backdoor] mprotect RWX failed");
        dlclose(libcrypto);
        return;
    }

    /* Escrivim el patch */
    memcpy(target, PATCH_BYTES, sizeof(PATCH_BYTES));

    /* Restaurem permisos originals (rx) */
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);

    fprintf(stderr, "[mock_backdoor] Patch aplicat. Primers bytes ara: ");
    for (int i = 0; i < 8; i++) {
        fprintf(stderr, "%02x ", ((uint8_t*)target)[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "[mock_backdoor] RSA_public_decrypt PATCHAT en RAM (0x%lx)\n", addr);

    dlclose(libcrypto);
}

/* Constructor: s'executa quan la biblioteca es carrega, ABANS de main() */
__attribute__((constructor))
static void backdoor_init(void) {
    fprintf(stderr, "[mock_backdoor] Constructor executat (simula liblzma _init maliciós)\n");
    patch_symbol();
}
