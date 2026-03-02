#!/bin/bash
# simulate_hook.sh — Simula el hook que CVE-2024-3094 faria a RSA_public_decrypt
# en la memòria del procés sshd. Permet verificar que got-auditor ho detecta.
#
# Funcionament:
#   El backdoor xz sobreescriu els primers bytes de RSA_public_decrypt a libcrypto
#   amb un JMP a codi maliciós. Aquest script fa el mateix però amb NOPs benignes.
#   Disc: bytes originals de RSA_public_decrypt
#   RAM:  primers 4 bytes sobreescrits amb 0x90909090 (NOP sled)
#   → got-auditor ha de reportar [!!! CODI PATCHAT !!!] RSA_public_decrypt

set -e

SSHD_PID=$(pgrep -xn sshd)
if [ -z "$SSHD_PID" ]; then
    echo "[!] No s'ha trobat cap procés sshd"
    exit 1
fi

# Volem el listener principal (el que té -D i és fill directe de PID 1/systemd),
# no els processos fills que gestionen sessions actives.
# El listener té ppid=1 (o ppid del systemd) i és propietat de root.
LISTENER_PID=$(ps -eo pid,ppid,user,args \
    | awk '$3=="root" && /sshd.*-D/ {print $1}' \
    | head -1)
if [ -n "$LISTENER_PID" ]; then
    SSHD_PID=$LISTENER_PID
fi
echo "[*] PID sshd listener: $SSHD_PID"

# Troba la base de libcrypto en memòria del procés sshd
LIBCRYPTO_BASE=$(grep libcrypto /proc/$SSHD_PID/maps | head -1 | awk -F- '{print "0x"$1}')
echo "[*] Base libcrypto en RAM: $LIBCRYPTO_BASE"

# Trobar l'adreça de RSA_public_decrypt via nm/objdump
LIBCRYPTO_PATH=$(grep -m1 libcrypto /proc/$SSHD_PID/maps | awk '{print $6}')
echo "[*] Path libcrypto: $LIBCRYPTO_PATH"

# Provem diverses eines per trobar l'offset del símbol
RSA_OFFSET=$(nm -D "$LIBCRYPTO_PATH" 2>/dev/null | grep " RSA_public_decrypt$" | awk '{print "0x"$1}')
if [ -z "$RSA_OFFSET" ]; then
    RSA_OFFSET=$(objdump -T "$LIBCRYPTO_PATH" 2>/dev/null | grep "RSA_public_decrypt$" | awk '{print "0x"$1}')
fi
if [ -z "$RSA_OFFSET" ]; then
    # readelf sempre disponible a Debian/Ubuntu
    RSA_OFFSET=$(readelf -Ws "$LIBCRYPTO_PATH" 2>/dev/null \
        | awk '/RSA_public_decrypt$/ && $5=="GLOBAL" {print "0x"$2; exit}')
fi
if [ -z "$RSA_OFFSET" ]; then
    echo "[!] No s'ha pogut trobar RSA_public_decrypt. Instal·la binutils:"
    echo "    sudo apt-get install -y binutils"
    exit 1
fi
echo "[*] Offset RSA_public_decrypt al disc: $RSA_OFFSET"

# Adreça real en RAM = base_mínima + offset
# La base mínima és el primer mapeig de libcrypto
BASE_MIN=$(awk -F'[-p ]' '/libcrypto/{print "0x"$1; exit}' /proc/$SSHD_PID/maps)
RSA_RAM_ADDR=$(python3 -c "print(hex($BASE_MIN + $RSA_OFFSET))")
echo "[*] Adreça RSA_public_decrypt en RAM: $RSA_RAM_ADDR"

echo ""
echo "[*] Aplicant patch NOP (simulació backdoor) via GDB..."
echo "    Sobreescrivint primers 4 bytes amb 0x90909090 (NOP sled)"

# Usem GDB per escriure en la memòria del procés
# (requereix que el segment r-xp sigui temporalment writable, com fa el backdoor real)
gdb -batch -q \
    -ex "attach $SSHD_PID" \
    -ex "set confirm off" \
    -ex "set *(int*)($RSA_RAM_ADDR) = 0x90909090" \
    -ex "detach" \
    -ex "quit" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[*] Patch aplicat correctament."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " Ara executa got-auditor apuntant al PID correcte:"
    echo ""
    echo "   sudo /got-auditor/target/debug/got_auditor -t sshd --pid $SSHD_PID --check-code"
    echo ""
    echo " Hauries de veure:"
    echo "   [!!! CODI PATCHAT !!!] 'RSA_public_decrypt' té bytes modificats en RAM!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "[!] Error aplicant el patch. Assegura't que gdb està instal·lat:"
    echo "    sudo apt-get install -y gdb"
fi
