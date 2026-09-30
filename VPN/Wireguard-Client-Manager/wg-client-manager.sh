#!/bin/sh
# =============================================================================
# wg-client-manager.sh
# Versao    : 1.4.1 (2026-09-29)
# Projeto   : EdenCore - Comunidade de Infraestrutura de TI
# Instrutor : Daniel Selbach Figueiró
# Funcao    : criar e gerenciar clientes WireGuard (wg-quick) via menu interativo.
#
# Transparencia: este script foi desenvolvido com auxilio de IA (Claude, da
# Anthropic). O codigo foi revisado, testado e validado pelo instrutor antes
# da publicacao.
#
# Historico:
#   1.0.0  Versao inicial: menu, instalacao multi-distro, criacao de cliente.
#   1.1.0  PSK passa a ser apenas informada (gerada no servidor).
#   1.2.0  Nova opcao de menu para exibir a chave publica do cliente e o
#          bloco de cadastro do peer no servidor.
#   1.2.1  Chave publica exibida sem codigo de cor (copia limpa), checagem de
#          integridade par privada/publica e listagem sem quebra de coluna.
#   1.3.0  Licoes de campo (S2C com MikroTik):
#          - IP do servidor no tunel adicionado como /32 no AllowedIPs.
#          - Deteccao de sobreposicao do tunel com a rede local.
#          - Remocao de duplicados no AllowedIPs.
#          - Diagnostico de handshake apos subir o tunel.
#          - Rotacao do par de chaves com comando "set" pronto p/ o servidor.
#          - Atualizacao de PSK sem expor o segredo.
#          - Exibicao do .conf com chaves ocultas (suporte sem vazamento).
#   1.4.0  Modulo de debug/troubleshooting:
#          - Log detalhado do modulo WireGuard do kernel (dynamic debug).
#          - Captura guiada com relatorio: kernel log, UDP (tcpdump),
#            amostras de handshake/transfer, rotas e analise automatica.
#          - Acompanhamento ao vivo; debug sempre desligado ao sair.
#   1.4.1  Destino dos logs sempre informado na tela (antes e depois da
#          captura); gravacao opcional do modo ao vivo em arquivo; listar e
#          exibir relatorios salvos. Nenhum log sai da maquina.
#
# Seguranca por Design:
#   - Executa somente como root; umask 077 em todo o fluxo (pastas 700, arquivos 600).
#   - Private key gerada localmente com "wg genkey", nunca exibida na tela.
#   - PSK e gerada no SERVIDOR; aqui e apenas colada (sem eco) e gravada em arquivo 600.
#   - Toda entrada (nome, IP, CIDR, porta, chave, DNS) e validada antes de gravar.
#   - Segredos nunca passam como argumento de comando externo (invisiveis ao "ps").
#   - Opcao de exibir .conf com chaves ocultas para envio a suporte.
#   - Nao altera firewall, ip_forward nem NAT do host (menor privilegio).
#   - Remocao de tunel exige confirmacao digitando o nome exato.
#
# Estrutura gerada por tunel:
#   /etc/wireguard/<tunel>/privatekey      (600)
#   /etc/wireguard/<tunel>/publickey       (600)
#   /etc/wireguard/<tunel>/presharedkey    (600, somente se usada)
#   /etc/wireguard/<tunel>/<tunel>.conf    (600)
#   /etc/wireguard/<tunel>.conf -> <tunel>/<tunel>.conf  (symlink p/ wg-quick e wg-quick@)
#
# Compatibilidade: POSIX sh (bash, dash, ash/busybox).
# Gerenciadores  : apt-get, dnf, yum, zypper, pacman, apk, xbps-install, emerge.
# Init           : systemd e OpenRC (habilitar no boot).
#
# Uso: sudo sh wg-client-manager.sh
# =============================================================================

# shellcheck disable=SC2154,SC1091  # vars atribuidas via eval; os-release lido em runtime
set -u
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

VERSION="1.4.1"
WG_DIR="${WG_DIR:-/etc/wireguard}"
LOG_DIR="${WG_LOG_DIR:-/var/log/wg-client-manager}"
DYN_CTRL="/sys/kernel/debug/dynamic_debug/control"
DEBUG_ACTIVE=0

# ----------------------------------------------------------------------------
# Saida
# ----------------------------------------------------------------------------
if [ -t 1 ]; then
    C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m')
    C_Y=$(printf '\033[33m'); C_B=$(printf '\033[36m'); C_N=$(printf '\033[0m')
else
    C_R=""; C_G=""; C_Y=""; C_B=""; C_N=""
fi

msg_ok()   { printf '%s[OK]%s %s\n'    "$C_G" "$C_N" "$1"; }
msg_err()  { printf '%s[ERRO]%s %s\n'  "$C_R" "$C_N" "$1" >&2; }
msg_warn() { printf '%s[AVISO]%s %s\n' "$C_Y" "$C_N" "$1"; }
msg_info() { printf '%s[INFO]%s %s\n'  "$C_B" "$C_N" "$1"; }

restore_tty() { stty echo 2>/dev/null || true; }

# Debug do kernel nunca fica ligado por esquecimento: desligado em qualquer saida.
debug_off() {
    if [ "$DEBUG_ACTIVE" -eq 1 ] && [ -e "$DYN_CTRL" ]; then
        echo 'module wireguard -p' > "$DYN_CTRL" 2>/dev/null
    fi
    DEBUG_ACTIVE=0
}
trap 'debug_off' EXIT
trap 'restore_tty; debug_off; printf "\n"; exit 130' INT TERM

pause() {
    printf '\nPressione Enter para continuar...'
    read -r _p || true
}

# ask VAR "Pergunta" [padrao]  -> le linha e grava em VAR
ask() {
    printf '%s' "$2"
    [ -n "${3:-}" ] && printf ' [%s]' "$3"
    printf ': '
    IFS= read -r _ans || { printf '\n'; msg_err "Entrada encerrada."; exit 1; }
    [ -z "$_ans" ] && _ans=${3:-}
    eval "$1=\$_ans"
}

# ask_secret VAR "Pergunta"  -> leitura sem eco
ask_secret() {
    printf '%s: ' "$2"
    stty -echo 2>/dev/null
    IFS= read -r _ans || _ans=""
    restore_tty
    printf '\n'
    eval "$1=\$_ans"
}

confirm() {
    ask _c "$1 [s/N]"
    case "$_c" in s|S|sim|SIM|y|Y) return 0 ;; *) return 1 ;; esac
}

# ----------------------------------------------------------------------------
# Validacoes
# ----------------------------------------------------------------------------
# Nome do tunel: minusculas, numeros, "-" e "_", inicia com letra, max 15
# (limite IFNAMSIZ do kernel Linux; compativel com wg-quick e systemd).
valid_tunnel_name() {
    printf '%s' "$1" | grep -Eq '^[a-z][a-z0-9_-]{0,14}$'
}

valid_port() {
    case "$1" in ''|*[!0-9]*|0*) return 1 ;; esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_keepalive() {
    [ "$1" = "0" ] && return 0
    valid_port "$1"
}

valid_ipv4() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    _ifs4=$IFS; IFS=.
    # shellcheck disable=SC2086
    set -- $1
    IFS=$_ifs4
    for _oct in "$@"; do
        case "$_oct" in 0?*) return 1 ;; esac
        [ "$_oct" -le 255 ] || return 1
    done
    return 0
}

valid_ipv6() {
    [ "${#1}" -le 45 ] || return 1
    printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:.]+$' || return 1
    case "$1" in *:*) ;; *) return 1 ;; esac
    case "$1" in *:::*) return 1 ;; esac
    _rest=${1#*::}
    if [ "$_rest" != "$1" ]; then
        case "$_rest" in *::*) return 1 ;; esac
    fi
    return 0
}

valid_ip() { valid_ipv4 "$1" || valid_ipv6 "$1"; }

valid_cidr() {
    case "$1" in */*) ;; *) return 1 ;; esac
    _addr=${1%/*}; _pfx=${1##*/}
    case "$_pfx" in ''|*[!0-9]*|0?*) return 1 ;; esac
    if valid_ipv4 "$_addr"; then
        [ "$_pfx" -le 32 ]
    elif valid_ipv6 "$_addr"; then
        [ "$_pfx" -le 128 ]
    else
        return 1
    fi
}

valid_fqdn() {
    [ "${#1}" -le 253 ] || return 1
    printf '%s' "$1" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}

# Chave WireGuard: base64 de 32 bytes (44 caracteres terminando em "=")
valid_wgkey() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'
}

# normalize_list "a, b,c" validador -> imprime "a, b, c" ou retorna 1
normalize_list() {
    _raw=$(printf '%s' "$1" | tr -d ' \t')
    [ -n "$_raw" ] || return 1
    case "$_raw" in ,*|*,|*,,*) return 1 ;; esac
    _out=""
    _ifsl=$IFS; IFS=,; set -f
    for _item in $_raw; do
        if ! "$2" "$_item"; then
            IFS=$_ifsl; set +f
            return 1
        fi
        case ", $_out, " in *", $_item, "*) continue ;; esac
        _out="${_out:+$_out, }$_item"
    done
    IFS=$_ifsl; set +f
    printf '%s' "$_out"
}

# ----------------------------------------------------------------------------
# Deteccao de ambiente
# ----------------------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg_err "Execute como root: sudo sh $0"
        exit 1
    fi
}

wg_installed() {
    command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1
}

kernel_support() {
    [ -d /sys/module/wireguard ] && return 0
    modprobe wireguard >/dev/null 2>&1 && return 0
    command -v wireguard-go >/dev/null 2>&1 && return 0
    return 1
}

init_system() {
    if [ -d /run/systemd/system ]; then
        printf 'systemd'
    elif command -v rc-update >/dev/null 2>&1; then
        printf 'openrc'
    else
        printf 'desconhecido'
    fi
}

detect_pm() {
    for _pm in apt-get dnf yum zypper pacman apk xbps-install emerge; do
        if command -v "$_pm" >/dev/null 2>&1; then
            printf '%s' "$_pm"
            return 0
        fi
    done
    return 1
}

tunnel_exists() {
    [ -f "$WG_DIR/$1/$1.conf" ]
}

tunnel_is_up() {
    ip link show "$1" >/dev/null 2>&1
}

check_install() {
    printf '\n--- Verificacao do ambiente ---\n'
    if [ -r /etc/os-release ]; then
        _os=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$ID}")
        msg_info "Sistema: $_os | Kernel: $(uname -r) | Init: $(init_system)"
    fi

    if command -v wg >/dev/null 2>&1; then msg_ok "wg encontrado: $(command -v wg)"
    else msg_err "wg NAO encontrado."; fi

    if command -v wg-quick >/dev/null 2>&1; then msg_ok "wg-quick encontrado: $(command -v wg-quick)"
    else msg_err "wg-quick NAO encontrado."; fi

    if command -v ip >/dev/null 2>&1; then msg_ok "iproute2 (ip) encontrado."
    else msg_err "comando ip NAO encontrado."; fi

    if kernel_support; then msg_ok "Suporte WireGuard no kernel (ou wireguard-go) disponivel."
    else msg_warn "Modulo wireguard indisponivel. Kernel < 5.6 exige wireguard-dkms ou wireguard-go."; fi

    if command -v resolvconf >/dev/null 2>&1; then msg_ok "resolvconf encontrado (diretiva DNS funcional)."
    else msg_warn "resolvconf ausente: tuneis com DNS vao falhar no wg-quick."; fi

    if ! wg_installed; then
        printf '\n'
        msg_warn "WireGuard NAO instalado. Use a opcao 2 do menu para instalar."
    fi
}

# ----------------------------------------------------------------------------
# Instalacao
# ----------------------------------------------------------------------------
install_resolvconf() {
    command -v resolvconf >/dev/null 2>&1 && return 0

    # Com systemd-resolved ativo, usa o modo de compatibilidade do resolvectl
    # em vez de instalar openresolv (evita conflito no /etc/resolv.conf).
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if [ "$1" = "apt-get" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-resolved >/dev/null 2>&1 || true
        fi
        if ! command -v resolvconf >/dev/null 2>&1 && command -v resolvectl >/dev/null 2>&1; then
            ln -sf "$(command -v resolvectl)" /usr/local/sbin/resolvconf
        fi
    else
        case "$1" in
            apt-get)      DEBIAN_FRONTEND=noninteractive apt-get install -y openresolv ;;
            dnf)          dnf install -y openresolv || dnf install -y systemd-resolved ;;
            yum)          yum install -y openresolv ;;
            zypper)       zypper --non-interactive install openresolv ;;
            pacman)       pacman -S --noconfirm --needed openresolv ;;
            apk)          apk add --no-cache openresolv ;;
            xbps-install) xbps-install -y openresolv ;;
            emerge)       emerge --ask=n net-dns/openresolv ;;
        esac
    fi

    if command -v resolvconf >/dev/null 2>&1; then
        msg_ok "resolvconf disponivel."
    else
        msg_warn "Nao foi possivel disponibilizar resolvconf. Use tuneis sem DNS ou instale manualmente."
    fi
}

install_wg() {
    _pm=$(detect_pm) || {
        msg_err "Gerenciador de pacotes nao suportado. Instale wireguard-tools e iproute2 manualmente."
        return 1
    }
    msg_info "Gerenciador detectado: $_pm"

    case "$_pm" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get update &&
            DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iproute2 ;;
        dnf)
            dnf install -y wireguard-tools iproute ||
            { dnf install -y epel-release && dnf install -y wireguard-tools iproute; } ;;
        yum)
            yum install -y epel-release && yum install -y wireguard-tools iproute ;;
        zypper)
            zypper --non-interactive install wireguard-tools iproute2 ;;
        pacman)
            pacman -S --noconfirm --needed wireguard-tools iproute2 ||
            { msg_warn "Falhou. Rode 'pacman -Syu' e tente novamente."; false; } ;;
        apk)
            apk add --no-cache wireguard-tools iproute2 ;;
        xbps-install)
            xbps-install -Sy wireguard-tools iproute2 ;;
        emerge)
            emerge --ask=n net-vpn/wireguard-tools sys-apps/iproute2 ;;
    esac || { msg_err "Falha na instalacao do WireGuard."; return 1; }

    install_resolvconf "$_pm"

    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"

    if kernel_support; then
        msg_ok "Modulo WireGuard carregado/disponivel."
    else
        msg_warn "Kernel sem modulo WireGuard. Instale wireguard-dkms (kernel < 5.6) ou wireguard-go."
    fi

    if wg_installed; then
        msg_ok "WireGuard instalado: $(wg --version 2>/dev/null | head -n1)"
    else
        msg_err "wg/wg-quick continuam ausentes apos a instalacao."
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Chave publica do cliente + bloco de cadastro no servidor
# ----------------------------------------------------------------------------
# Converte "10.8.0.2/24" em "10.8.0.2/32" (ou /128 no IPv6): no servidor o
# AllowedIPs do peer deve ser apenas o host do cliente.
host_prefix() {
    _h=${1%/*}
    if valid_ipv4 "$_h"; then printf '%s/32' "$_h"; else printf '%s/128' "$_h"; fi
}

show_peer_info() {
    _d="$WG_DIR/$1"
    _pub=$(tr -d ' \t\r\n' < "$_d/publickey" 2>/dev/null) || { msg_err "publickey de '$1' nao encontrada."; return 1; }
    if ! valid_wgkey "$_pub"; then
        msg_err "publickey de '$1' com formato invalido. Recrie o cliente."
        return 1
    fi
    if command -v wg >/dev/null 2>&1 && [ "$(wg pubkey < "$_d/privatekey")" != "$_pub" ]; then
        msg_err "publickey nao corresponde a privatekey de '$1'. Recrie o cliente."
        return 1
    fi
    _addrs=$(grep -E '^Address[[:space:]]*=' "$_d/$1.conf" | head -n1 | sed 's/^[^=]*=[[:space:]]*//' | tr -d ' ')
    _srv_allowed=""
    _ifsp=$IFS; IFS=,
    for _a in $_addrs; do
        _srv_allowed="${_srv_allowed:+$_srv_allowed,}$(host_prefix "$_a")"
    done
    IFS=$_ifsp

    printf '\n--- Cadastre este peer no SERVIDOR (tunel %s) ---\n' "$1"
    # Sem codigo de cor na chave: copia do terminal sai limpa.
    printf 'Chave publica do cliente (44 caracteres):\n%s\n' "$_pub"
    printf 'Arquivo                 : %s/publickey\n\n' "$_d"

    printf '# wg-quick (Linux) - adicionar no .conf do servidor:\n'
    printf '[Peer]\n# %s\nPublicKey = %s\n' "$1" "$_pub"
    [ -f "$_d/presharedkey" ] && printf 'PresharedKey = <mesma PSK gerada no servidor para este peer>\n'
    printf 'AllowedIPs = %s\n\n' "$(printf '%s' "$_srv_allowed" | sed 's/,/, /g')"

    printf '# MikroTik RouterOS v7:\n'
    printf '/interface wireguard peers add interface=<wg-servidor> name="%s" public-key="%s" allowed-address=%s' "$1" "$_pub" "$_srv_allowed"
    [ -f "$_d/presharedkey" ] && printf ' preshared-key="<PSK gerada no servidor>"'
    printf ' comment="%s"\n' "$1"
    printf '\n# Conferir no servidor ANTES de testar no cliente:\n'
    printf '/interface wireguard peers print detail where public-key="%s"\n' "$_pub"
    printf '# allowed-address deve conter apenas o(s) /32 do cliente (nunca as LANs do proprio servidor).\n'
}

# ----------------------------------------------------------------------------
# Utilitarios de configuracao (sem expor segredo em argumento de processo)
# ----------------------------------------------------------------------------
# rewrite_conf ARQ NOVA_PRIV MODO_PSK PSK
#   NOVA_PRIV vazio = mantem; MODO_PSK: keep | set | del
rewrite_conf() {
    _rf=$1; _rtmp="$1.tmp"
    while IFS= read -r _l || [ -n "$_l" ]; do
        case "$_l" in
            PrivateKey*=*)
                if [ -n "$2" ]; then printf 'PrivateKey = %s\n' "$2"; else printf '%s\n' "$_l"; fi ;;
            PresharedKey*=*)
                if [ "$3" = "keep" ]; then printf '%s\n' "$_l"; fi ;;
            PublicKey*=*)
                printf '%s\n' "$_l"
                if [ "$3" = "set" ]; then printf 'PresharedKey = %s\n' "$4"; fi ;;
            *)  printf '%s\n' "$_l" ;;
        esac
    done < "$_rf" > "$_rtmp" && mv "$_rtmp" "$_rf" && chmod 600 "$_rf"
}

# IP do servidor dentro do tunel, gravado como comentario no .conf
server_tunnel_ip() {
    grep -E '^# ServerTunnelIP[[:space:]]*=' "$WG_DIR/$1/$1.conf" 2>/dev/null |
        head -n1 | sed 's/^[^=]*=[[:space:]]*//'
}

# Rotas locais que se sobrepoem a cada CIDR (exceto default)
route_conflicts() {
    printf '%s\n' "$1" | tr -d ' ' | tr ',' '\n' | while IFS= read -r _c; do
        [ -n "$_c" ] || continue
        case "$_c" in 0.0.0.0/0|::/0) continue ;; esac
        case "$_c" in *:*) _fam=-6 ;; *) _fam=-4 ;; esac
        { ip "$_fam" route show to match "$_c" 2>/dev/null
          ip "$_fam" route show to root  "$_c" 2>/dev/null; } |
            grep -v '^default' | sort -u | sed "s|^|  $_c  x  |"
    done
}

# IP responde localmente (fora da VPN)? Foi a causa de um falso positivo em campo.
probe_local_ip() {
    command -v ping >/dev/null 2>&1 || return 1
    ping -c1 -W1 "$1" >/dev/null 2>&1
}

# ----------------------------------------------------------------------------
# Diagnostico de handshake
# ----------------------------------------------------------------------------
# Evidencia de campo: quando o servidor descarta a iniciacao (chave publica
# desconhecida) OU quando o cliente descarta a resposta (PSK divergente), o
# contador "received" do cliente fica em 0 nos dois casos. Quem diferencia e o
# contador do peer no SERVIDOR.
diagnose_tunnel() {
    _t=$1
    if ! tunnel_is_up "$_t"; then
        msg_err "Tunel $_t inativo. Ative antes de diagnosticar."
        return 1
    fi
    _sip=$(server_tunnel_ip "$_t")
    [ -n "$_sip" ] && ping -c1 -W1 "$_sip" >/dev/null 2>&1 &

    printf 'Aguardando handshake (ate 15s)'
    _i=0; _hs=0
    while [ "$_i" -lt 15 ]; do
        _hs=$(wg show "$_t" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
        [ "${_hs:-0}" -gt 0 ] && break
        printf '.'; sleep 1; _i=$((_i + 1))
    done
    printf '\n'
    wait 2>/dev/null

    _rx=$(wg show "$_t" transfer 2>/dev/null | awk 'NR==1{print $2}')
    _tx=$(wg show "$_t" transfer 2>/dev/null | awk 'NR==1{print $3}')
    _pub=$(tr -d ' \t\r\n' < "$WG_DIR/$_t/publickey")
    _now=$(date +%s)

    if [ "${_hs:-0}" -gt 0 ]; then
        _age=$((_now - _hs))
        if [ "$_age" -le 180 ]; then
            msg_ok "Handshake OK ha ${_age}s | recebido ${_rx:-0} B, enviado ${_tx:-0} B."
            if [ -n "$_sip" ]; then
                if ping -c2 -W2 "$_sip" >/dev/null 2>&1; then
                    msg_ok "Servidor no tunel ($_sip) responde."
                else
                    msg_warn "Handshake OK, mas $_sip nao responde: verificar firewall input/ICMP no servidor."
                fi
            fi
            return 0
        fi
        msg_warn "Ultimo handshake ha ${_age}s (> 180s): sessao expirada ou sem trafego."
    else
        msg_err "Sem handshake. Enviado ${_tx:-0} B, recebido ${_rx:-0} B."
    fi

    printf '\nConfira no SERVIDOR (MikroTik) e compare os contadores rx/tx do peer:\n'
    printf '  /interface wireguard print detail\n'
    printf '  /interface wireguard peers print detail where public-key="%s"\n\n' "$_pub"
    printf 'Leitura:\n'
    printf '  - Nenhum peer encontrado ou rx/tx parados: servidor nao reconhece a chave publica\n'
    printf '    do cliente (peer com chave antiga ou colada errada) ou UDP bloqueado no caminho.\n'
    printf '  - rx e tx do peer crescendo, sem handshake: PSK divergente entre as pontas.\n'
    printf '  - public-key da interface do servidor diferente de "PublicKey" do [Peer] no cliente:\n'
    printf '    chave do servidor errada no cliente.\n'
    printf '  - Depois de todo "set" no servidor, rode o print detail antes de testar de novo.\n'
    return 1
}

# ----------------------------------------------------------------------------
# Rotacao de chaves, PSK e exibicao segura
# ----------------------------------------------------------------------------
rotate_keys() {
    select_tunnel _rt || return 1
    _d="$WG_DIR/$_rt"
    msg_warn "O tunel para de funcionar ate o servidor receber a nova chave publica."
    confirm "Rotacionar o par de chaves de '$_rt'?" || { msg_info "Cancelado."; return 0; }

    _old=$(tr -d ' \t\r\n' < "$_d/publickey")
    _was_up=0
    if tunnel_is_up "$_rt"; then _was_up=1; wg-quick down "$_rt"; fi

    if ! { wg genkey > "$_d/privatekey.new" && wg pubkey < "$_d/privatekey.new" > "$_d/publickey.new"; }; then
        rm -f "$_d/privatekey.new" "$_d/publickey.new"
        msg_err "Falha ao gerar novo par. Chaves atuais mantidas."
        return 1
    fi
    mv "$_d/privatekey.new" "$_d/privatekey"
    mv "$_d/publickey.new" "$_d/publickey"
    rewrite_conf "$_d/$_rt.conf" "$(cat "$_d/privatekey")" keep ""
    chmod 600 "$_d"/*
    _new=$(tr -d ' \t\r\n' < "$_d/publickey")
    msg_ok "Novo par gerado para '$_rt'."

    printf '\n--- Atualize o peer no SERVIDOR ---\n'
    printf 'Nova chave publica do cliente:\n%s\n\n' "$_new"
    printf '# MikroTik RouterOS v7 (localiza o peer pela chave antiga):\n'
    printf '/interface wireguard peers set [find public-key="%s"] public-key="%s"\n' "$_old" "$_new"
    printf '/interface wireguard peers print detail where public-key="%s"\n\n' "$_new"
    printf '# wg-quick (Linux): troque "PublicKey = %s" por "PublicKey = %s"\n' "$_old" "$_new"

    if [ "$_was_up" -eq 1 ] || confirm "Subir o tunel agora?"; then
        printf '\n'
        if confirm "Servidor ja atualizado com a nova chave publica?"; then
            tunnel_up "$_rt"
        else
            msg_info "Suba depois pela opcao 6 do menu."
        fi
    fi
}

update_psk() {
    select_tunnel _up || return 1
    _d="$WG_DIR/$_up"
    while :; do
        ask_secret _psk "Nova PSK gerada no servidor (Enter = remover PSK)"
        [ -z "$_psk" ] && break
        valid_wgkey "$_psk" && break
        msg_err "PSK invalida (44 caracteres base64 terminando em '=')."
    done

    if [ -n "$_psk" ]; then
        rewrite_conf "$_d/$_up.conf" "" set "$_psk"
        printf '%s\n' "$_psk" > "$_d/presharedkey"
        chmod 600 "$_d/presharedkey"
        msg_ok "PSK atualizada em '$_up'."
    else
        rewrite_conf "$_d/$_up.conf" "" del ""
        rm -f "$_d/presharedkey"
        msg_ok "PSK removida de '$_up'. Remova tambem no servidor (preshared-key=\"\")."
    fi
    _psk=""

    if tunnel_is_up "$_up"; then
        wg-quick down "$_up" && tunnel_up "$_up"
    fi
}

show_conf_masked() {
    select_tunnel _sc || return 1
    printf '\n'
    sed -E 's/^(PrivateKey|PresharedKey)[[:space:]]*=.*/\1 = <oculta>/' "$WG_DIR/$_sc/$_sc.conf"
    printf '\n'
    msg_info "Saida segura para enviar a suporte/chamado."
}

# ----------------------------------------------------------------------------
# Criacao do cliente
# ----------------------------------------------------------------------------
create_client() {
    if ! wg_installed; then
        msg_err "WireGuard nao instalado. Use a opcao 2 do menu."
        return 1
    fi
    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"

    printf '\n--- Novo cliente WireGuard ---\n'

    # 1. Nome do tunel
    while :; do
        ask TUN "Nome do tunel (a-z 0-9 - _, inicia com letra, max 15)"
        if ! valid_tunnel_name "$TUN"; then
            msg_err "Nome invalido. Ex.: wg-matriz, vpn_sp01. Sem maiusculas, espacos ou acentos."
            continue
        fi
        if [ -e "$WG_DIR/$TUN" ] || [ -e "$WG_DIR/$TUN.conf" ]; then
            msg_err "Ja existe configuracao para '$TUN' em $WG_DIR."
            continue
        fi
        if ip link show "$TUN" >/dev/null 2>&1; then
            msg_err "Ja existe uma interface de rede chamada '$TUN'."
            continue
        fi
        break
    done

    # 2. Endpoint do servidor
    while :; do
        ask SRV_HOST "IP ou hostname do servidor WireGuard"
        if valid_ipv4 "$SRV_HOST"; then
            SRV_FMT=$SRV_HOST; break
        elif valid_fqdn "$SRV_HOST"; then
            if command -v getent >/dev/null 2>&1 && ! getent hosts "$SRV_HOST" >/dev/null 2>&1; then
                msg_warn "$SRV_HOST nao resolve neste momento. Confira o DNS/DDNS do servidor."
            fi
            SRV_FMT=$SRV_HOST; break
        elif valid_ipv6 "$SRV_HOST"; then
            SRV_FMT="[$SRV_HOST]"; break
        fi
        msg_err "Endereco invalido. Informe IPv4, IPv6 ou FQDN (ex.: vpn.empresa.com.br)."
    done

    # 3. Porta
    while :; do
        ask SRV_PORT "Porta do servidor" "51820"
        valid_port "$SRV_PORT" && break
        msg_err "Porta invalida (1-65535)."
    done

    # 4. Chave publica do servidor (obrigatoria para o [Peer])
    while :; do
        ask SRV_PUB "Chave publica do servidor"
        valid_wgkey "$SRV_PUB" && break
        msg_err "Chave invalida. Deve ter 44 caracteres base64 terminando em '='."
    done

    # 5. Endereco do cliente dentro do tunel
    while :; do
        ask ADDR_IN "Endereco do cliente no tunel (CIDR, ex.: 10.8.0.2/32)"
        ADDR=$(normalize_list "$ADDR_IN" valid_cidr) && break
        msg_err "CIDR invalido. Varios separados por virgula: 10.8.0.2/32, fd00::2/128"
    done

    # 6. Allowed address
    while :; do
        ask ALLOWED_IN "Allowed address (CIDR, ex.: 10.8.0.0/24, 192.168.10.0/24)"
        ALLOWED=$(normalize_list "$ALLOWED_IN" valid_cidr) && break
        msg_err "Lista invalida. Use CIDR separado por virgula."
    done
    case "$ALLOWED" in
        *0.0.0.0/0*|*::/0*) msg_warn "Full tunnel: todo o trafego do host saira pela VPN. Garanta que o endpoint nao dependa da propria VPN." ;;
    esac

    # 6b. IP do servidor dentro do tunel: vira /32 no AllowedIPs para permitir
    #     gerencia e teste de ping do proprio servidor pela VPN.
    SRV_TIP=""
    while :; do
        ask SRV_TIP "IP do servidor dentro do tunel (opcional, ex.: 172.16.0.1 | Enter = pular)"
        [ -z "$SRV_TIP" ] && break
        valid_ip "$SRV_TIP" && break
        msg_err "IP invalido."
        SRV_TIP=""
    done
    if [ -n "$SRV_TIP" ]; then
        ALLOWED=$(normalize_list "$ALLOWED, $(host_prefix "$SRV_TIP")" valid_cidr)
        if probe_local_ip "$SRV_TIP"; then
            msg_warn "$SRV_TIP JA responde na rede local (fora da VPN): $(ip route get "$SRV_TIP" 2>/dev/null | head -n1)"
            msg_warn "Sobreposicao: com o tunel ativo, a rota /32 pela VPN esconde esse IP local."
            msg_warn "Recomendado: sub-rede de tunel exclusiva no servidor."
            confirm "Continuar mesmo assim?" || { msg_info "Operacao cancelada."; return 0; }
        fi
    fi

    # 6c. Sobreposicao do AllowedIPs com rotas locais existentes
    _conflicts=$(route_conflicts "$ALLOWED")
    if [ -n "$_conflicts" ]; then
        msg_warn "AllowedIPs sobrepoe rotas ja existentes neste host (rede x rota):"
        printf '%s\n' "$_conflicts"
        msg_warn "Com o tunel ativo o trafego dessas faixas pode ir para o lugar errado."
        confirm "Continuar mesmo assim?" || { msg_info "Operacao cancelada."; return 0; }
    fi

    # 7. Preshared key (opcional)
    # A PSK e gerada no servidor (wg genpsk / RouterOS) e colada aqui.
    PSK=""
    while :; do
        ask_secret PSK "Preshared key gerada no servidor (Enter = sem PSK)"
        [ -z "$PSK" ] && break
        valid_wgkey "$PSK" && break
        msg_err "PSK invalida (44 caracteres base64 terminando em '=')."
        PSK=""
    done

    # 8. DNS (opcional)
    DNS=""
    while :; do
        ask DNS_IN "DNS (opcional, ex.: 10.8.0.1, 1.1.1.1 | Enter = sem DNS)"
        [ -z "$DNS_IN" ] && break
        DNS=$(normalize_list "$DNS_IN" valid_ip) && break
        msg_err "DNS invalido. Informe apenas IPs separados por virgula."
        DNS=""
    done
    if [ -n "$DNS" ] && ! command -v resolvconf >/dev/null 2>&1; then
        msg_warn "resolvconf ausente: wg-quick vai falhar ao aplicar DNS. Use a opcao 2 para instalar."
    fi

    # 9. Persistent keepalive
    while :; do
        ask KA "Persistent keepalive em segundos (0 = desativado)" "25"
        valid_keepalive "$KA" && break
        msg_err "Valor invalido (0-65535)."
    done

    # Resumo
    printf '\n--- Resumo ---\n'
    printf 'Tunel ............: %s\n' "$TUN"
    printf 'Endpoint .........: %s:%s\n' "$SRV_FMT" "$SRV_PORT"
    printf 'Pubkey servidor ..: %s\n' "$SRV_PUB"
    printf 'Address ..........: %s\n' "$ADDR"
    printf 'AllowedIPs .......: %s\n' "$ALLOWED"
    printf 'Servidor no tunel : %s\n' "${SRV_TIP:-nao informado}"
    if [ -n "$PSK" ]; then printf 'PresharedKey .....: [definida]\n'; else printf 'PresharedKey .....: nao\n'; fi
    printf 'DNS ..............: %s\n' "${DNS:-nao}"
    printf 'Keepalive ........: %s\n' "$KA"
    printf 'Pasta ............: %s/%s\n\n' "$WG_DIR" "$TUN"

    if ! confirm "Gravar configuracao?"; then
        msg_info "Operacao cancelada. Nada foi gravado."
        return 0
    fi

    # Gravacao
    _dir="$WG_DIR/$TUN"
    _conf="$_dir/$TUN.conf"
    mkdir -m 700 "$_dir" || { msg_err "Falha ao criar $_dir"; return 1; }

    if ! { wg genkey > "$_dir/privatekey" && wg pubkey < "$_dir/privatekey" > "$_dir/publickey"; }; then
        msg_err "Falha ao gerar chaves. Revertendo."
        rm -rf "$_dir"
        return 1
    fi

    if [ -n "$PSK" ]; then
        printf '%s\n' "$PSK" > "$_dir/presharedkey"
    fi

    {
        printf '# Tunel WireGuard: %s\n' "$TUN"
        printf '# Gerado por wg-client-manager.sh v%s em %s\n' "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S')"
        if [ -n "$SRV_TIP" ]; then printf '# ServerTunnelIP = %s\n' "$SRV_TIP"; fi
        printf '\n'
        printf '[Interface]\n'
        printf 'PrivateKey = %s\n' "$(cat "$_dir/privatekey")"
        printf 'Address = %s\n' "$ADDR"
        if [ -n "$DNS" ]; then printf 'DNS = %s\n' "$DNS"; fi
        printf '\n[Peer]\n'
        printf 'PublicKey = %s\n' "$SRV_PUB"
        if [ -n "$PSK" ]; then printf 'PresharedKey = %s\n' "$PSK"; fi
        printf 'Endpoint = %s:%s\n' "$SRV_FMT" "$SRV_PORT"
        printf 'AllowedIPs = %s\n' "$ALLOWED"
        if [ "$KA" -gt 0 ]; then printf 'PersistentKeepalive = %s\n' "$KA"; fi
    } > "$_conf"

    chmod 600 "$_dir"/*
    ln -s "$TUN/$TUN.conf" "$WG_DIR/$TUN.conf"
    PSK=""

    msg_ok "Configuracao gravada em $_conf"
    show_peer_info "$TUN"


    printf '\n'
    if confirm "Ativar o tunel agora?"; then
        tunnel_up "$TUN"
    fi
}

# ----------------------------------------------------------------------------
# Gestao de tuneis
# ----------------------------------------------------------------------------
list_clients() {
    printf '\n%-16s %-6s %s\n' "TUNEL" "ESTADO" "ENDPOINT"
    _found=0
    for _d in "$WG_DIR"/*/; do
        [ -d "$_d" ] || continue
        _n=$(basename "$_d")
        tunnel_exists "$_n" || continue
        _found=1
        _ep=$(grep -E '^Endpoint[[:space:]]*=' "$WG_DIR/$_n/$_n.conf" | head -n1 | sed 's/^[^=]*=[[:space:]]*//')
        _pk=$(cat "$WG_DIR/$_n/publickey" 2>/dev/null || printf '-')
        if tunnel_is_up "$_n"; then _st="UP"; else _st="DOWN"; fi
        printf '%-16s %-6s %s\n' "$_n" "$_st" "$_ep"
        printf '  pubkey: %s\n' "$_pk"
    done
    [ "$_found" -eq 1 ] || msg_info "Nenhum cliente criado por este script em $WG_DIR."
}

# select_tunnel VAR -> pede nome e valida existencia
select_tunnel() {
    list_clients
    printf '\n'
    ask _sel "Nome do tunel"
    if ! valid_tunnel_name "$_sel" || ! tunnel_exists "$_sel"; then
        msg_err "Tunel '$_sel' nao encontrado."
        return 1
    fi
    eval "$1=\$_sel"
}

tunnel_up() {
    if tunnel_is_up "$1"; then
        msg_info "Tunel $1 ja esta ativo."
        return 0
    fi
    if wg-quick up "$1"; then
        msg_ok "Interface $1 ativa."
        diagnose_tunnel "$1"
    else
        msg_err "Falha ao subir $1. Verifique chave do servidor, endpoint, porta e firewall."
        return 1
    fi
}

tunnel_down() {
    if ! tunnel_is_up "$1"; then
        msg_info "Tunel $1 ja esta inativo."
        return 0
    fi
    wg-quick down "$1" && msg_ok "Tunel $1 desativado."
}

tunnel_boot() {
    case "$(init_system)" in
        systemd)
            systemctl enable "wg-quick@$1" && msg_ok "wg-quick@$1 habilitado no boot." ;;
        openrc)
            if [ -x /etc/init.d/wg-quick ]; then
                ln -sf wg-quick "/etc/init.d/wg-quick.$1" &&
                rc-update add "wg-quick.$1" default && msg_ok "wg-quick.$1 habilitado no boot."
            else
                msg_err "Script /etc/init.d/wg-quick ausente. Instale wireguard-tools-openrc (Alpine)."
                return 1
            fi ;;
        *)
            msg_warn "Init nao identificado. Adicione 'wg-quick up $1' na inicializacao manualmente."
            return 1 ;;
    esac
}

tunnel_noboot() {
    case "$(init_system)" in
        systemd) systemctl disable "wg-quick@$1" >/dev/null 2>&1 || true ;;
        openrc)
            rc-update del "wg-quick.$1" default >/dev/null 2>&1 || true
            rm -f "/etc/init.d/wg-quick.$1" ;;
    esac
}

show_status() {
    if ! wg_installed; then
        msg_err "WireGuard nao instalado."
        return 1
    fi
    # "wg show" nunca exibe private key; mascaramos o resto por garantia.
    wg show all 2>/dev/null | sed -e '/private key/d' -e '/preshared key/d'
    [ -n "$(wg show interfaces 2>/dev/null)" ] || msg_info "Nenhum tunel ativo."
}

remove_client() {
    select_tunnel _rm || return 1
    msg_warn "Isso apaga chaves e configuracao de '$_rm' definitivamente."
    ask _chk "Digite o nome do tunel para confirmar"
    if [ "$_chk" != "$_rm" ]; then
        msg_info "Confirmacao nao confere. Nada foi removido."
        return 0
    fi
    tunnel_is_up "$_rm" && wg-quick down "$_rm"
    tunnel_noboot "$_rm"
    rm -f "$WG_DIR/$_rm.conf"
    rm -rf "${WG_DIR:?}/$_rm"
    msg_ok "Cliente '$_rm' removido. Remova tambem o peer correspondente no servidor."
}

# ----------------------------------------------------------------------------
# Debug / troubleshooting
# ----------------------------------------------------------------------------
# O modulo WireGuard do kernel so registra eventos de handshake, keepalive e
# pacotes rejeitados quando o dynamic debug esta ativo. Sem ele o WireGuard e
# silencioso por design. Requer CONFIG_DYNAMIC_DEBUG e debugfs acessivel
# (Secure Boot com kernel lockdown bloqueia a escrita no debugfs).

lockdown_state() {
    [ -r /sys/kernel/security/lockdown ] || { printf 'n/d'; return; }
    sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown
}

debug_on() {
    [ -d /sys/module/wireguard ] || modprobe wireguard >/dev/null 2>&1
    if [ ! -e "$DYN_CTRL" ]; then
        mount -t debugfs none /sys/kernel/debug >/dev/null 2>&1
    fi
    if [ ! -e "$DYN_CTRL" ]; then
        msg_warn "Dynamic debug indisponivel (kernel sem CONFIG_DYNAMIC_DEBUG ou debugfs ausente)."
        return 1
    fi
    if echo 'module wireguard +p' > "$DYN_CTRL" 2>/dev/null; then
        DEBUG_ACTIVE=1
        return 0
    fi
    msg_warn "Escrita no dynamic debug negada. Kernel lockdown: $(lockdown_state)."
    msg_warn "Com Secure Boot ativo o log do kernel fica indisponivel; a captura UDP continua valida."
    return 1
}

debug_status() {
    printf '\n--- Status do debug ---\n'
    print_log_destinations
    msg_info "Kernel lockdown: $(lockdown_state)"
    if [ ! -e "$DYN_CTRL" ]; then
        msg_info "Dynamic debug: nao montado/disponivel."
    else
        _n=$(grep -c 'wireguard.*=p' "$DYN_CTRL" 2>/dev/null)
        if [ "${_n:-0}" -gt 0 ]; then
            msg_warn "Debug WireGuard ATIVO no kernel ($_n pontos). Desative ao terminar."
        else
            msg_ok "Debug WireGuard desativado."
        fi
    fi
    if command -v tcpdump >/dev/null 2>&1; then msg_ok "tcpdump disponivel."
    else msg_info "tcpdump ausente (instalado sob demanda na captura guiada)."; fi
    _nlog=$(find "$LOG_DIR" -type f -name '*.log' 2>/dev/null | wc -l)
    msg_info "Relatorios em $LOG_DIR: ${_nlog:-0}"
}

debug_force_off() {
    [ -e "$DYN_CTRL" ] && echo 'module wireguard -p' > "$DYN_CTRL" 2>/dev/null
    DEBUG_ACTIVE=0
    msg_ok "Debug WireGuard desativado no kernel."
}

ensure_tcpdump() {
    command -v tcpdump >/dev/null 2>&1 && return 0
    confirm "tcpdump nao instalado. Instalar agora (recomendado para a captura)?" || return 1
    _pm=$(detect_pm) || { msg_err "Gerenciador de pacotes nao suportado."; return 1; }
    case "$_pm" in
        apt-get)      DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump ;;
        dnf|yum)      "$_pm" install -y tcpdump ;;
        zypper)       zypper --non-interactive install tcpdump ;;
        pacman)       pacman -S --noconfirm --needed tcpdump ;;
        apk)          apk add --no-cache tcpdump ;;
        xbps-install) xbps-install -y tcpdump ;;
        emerge)       emerge --ask=n net-analyzer/tcpdump ;;
    esac >/dev/null 2>&1
    command -v tcpdump >/dev/null 2>&1
}

# Leitura do log do kernel desde um instante (journalctl) ou por diferenca de linhas (dmesg)
kernel_log_since() {
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        journalctl -k --since "@$1" --no-pager -o short-precise 2>/dev/null | grep -i 'wireguard'
    else
        dmesg 2>/dev/null | tail -n +"$(( $2 + 1 ))" | grep -i 'wireguard'
    fi
}

mask_secrets() {
    sed -E -e 's/^(PrivateKey|PresharedKey)[[:space:]]*=.*/\1 = <oculta>/' \
           -e 's/(private key|preshared key):.*/\1: (oculta)/'
}

# analyze_capture KLOG UDPLOG EP_IP EP_PORT HANDSHAKE_OK PING_OK PING_TOTAL SIP
analyze_capture() {
    _k=$1; _u=$2; _eip=$3; _ep=$4; _hsok=$5; _pok=$6; _ptot=$7; _sip=$8
    _init=$(grep -c 'Sending handshake initiation' "$_k" 2>/dev/null)
    _resp=$(grep -c 'Receiving handshake response' "$_k" 2>/dev/null)
    _inv=$(grep -c 'Invalid handshake' "$_k" 2>/dev/null)
    _kp=$(grep -c 'Keypair .* created' "$_k" 2>/dev/null)
    _unal=$(grep -c 'unallowed src IP' "$_k" 2>/dev/null)
    _noep=$(grep -c 'No valid endpoint' "$_k" 2>/dev/null)
    _klines=$(wc -l < "$_k" 2>/dev/null)
    _out=0; _in=0; _in92=0; _out148=0
    if [ -s "$_u" ]; then
        _out=$(grep -cF "> $_eip.$_ep:" "$_u")
        _in=$(grep -cF "$_eip.$_ep >" "$_u")
        _out148=$(grep -F "> $_eip.$_ep:" "$_u" | grep -c 'length 148')
        _in92=$(grep -F "$_eip.$_ep >" "$_u" | grep -c 'length 92')
    fi

    printf 'Kernel : iniciacoes=%s respostas=%s invalidos=%s keypairs=%s unallowed_src=%s sem_endpoint=%s (linhas=%s)\n' \
        "${_init:-0}" "${_resp:-0}" "${_inv:-0}" "${_kp:-0}" "${_unal:-0}" "${_noep:-0}" "${_klines:-0}"
    printf 'UDP    : saindo=%s (iniciacao 148B=%s) | chegando=%s (resposta 92B=%s)\n' \
        "$_out" "$_out148" "$_in" "$_in92"
    [ -n "$_sip" ] && printf 'Ping   : %s/%s respostas de %s\n' "$_pok" "$_ptot" "$_sip"
    printf '\n'

    _found=0
    if [ "$_hsok" -eq 1 ] || [ "${_kp:-0}" -gt 0 ]; then
        printf '[OK] Handshake estabelecido.\n'; _found=1
        if [ -n "$_sip" ] && [ "$_pok" -eq 0 ]; then
            printf '[CAUSA] Tunel OK, mas %s nao responde: firewall input/ICMP no servidor\n' "$_sip"
            printf '        ou IP do servidor no tunel diferente de %s.\n' "$_sip"
        fi
    else
        if [ "${_inv:-0}" -gt 0 ] || [ "$_in92" -gt 0 ]; then
            printf '[CAUSA] O servidor RESPONDE, mas a resposta e rejeitada pelo cliente.\n'
            printf '        Provavel: PSK divergente entre as pontas, ou PublicKey do servidor\n'
            printf '        errada no [Peer] do cliente.\n'; _found=1
        elif [ "$_out" -gt 0 ] || [ "${_init:-0}" -gt 0 ]; then
            if [ "$_in" -eq 0 ]; then
                printf '[CAUSA] Iniciacoes saem e NENHUM pacote volta do servidor.\n'
                printf '        Provavel: chave publica do cliente ausente/errada no peer do servidor,\n'
                printf '        UDP %s bloqueado no caminho, ou endpoint/porta incorretos.\n' "$_ep"; _found=1
            fi
        fi
        if [ "${_noep:-0}" -gt 0 ]; then
            printf '[CAUSA] Peer sem endpoint valido: verifique Endpoint e resolucao DNS/DDNS.\n'; _found=1
        fi
    fi
    if [ "${_unal:-0}" -gt 0 ]; then
        printf '[CAUSA] Pacotes com IP de origem fora do AllowedIPs do cliente foram descartados.\n'
        printf '        Inclua a rede de origem no AllowedIPs ou revise NAT/masquerade no servidor.\n'; _found=1
    fi
    if [ "$_found" -eq 0 ]; then
        printf '[INFO] Sem evidencia conclusiva. Aumente a duracao da captura ou habilite\n'
        printf '       o log do lado do servidor (comandos abaixo).\n'
    fi
    if [ "${_klines:-0}" -eq 0 ] && [ ! -s "$_u" ]; then
        printf '[AVISO] Sem log do kernel e sem captura UDP: analise limitada.\n'
    fi
}

debug_capture() {
    select_tunnel _dt || return 1
    while :; do
        ask _dur "Duracao da captura em segundos (10-600)" "30"
        case "$_dur" in ''|*[!0-9]*) ;; *) [ "$_dur" -ge 10 ] && [ "$_dur" -le 600 ] && break ;; esac
        msg_err "Informe um valor entre 10 e 600."
    done
    _restart=0
    confirm "Reiniciar o tunel no inicio (registra o handshake desde o zero)?" && _restart=1

    mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
    _stamp=$(date '+%Y%m%d-%H%M%S')
    _log="$LOG_DIR/${_dt}-${_stamp}.log"
    _klog="$LOG_DIR/.${_dt}-${_stamp}.klog"
    _ulog="$LOG_DIR/.${_dt}-${_stamp}.udp"
    : > "$_log"; : > "$_klog"; : > "$_ulog"

    _kdebug=0; debug_on && _kdebug=1
    _t0=$(date +%s)
    _dm0=$(dmesg 2>/dev/null | wc -l)

    if [ "$_restart" -eq 1 ] && tunnel_is_up "$_dt"; then
        wg-quick down "$_dt" >> "$_log" 2>&1
    fi
    tunnel_is_up "$_dt" || wg-quick up "$_dt" >> "$_log" 2>&1

    _epraw=$(wg show "$_dt" endpoints 2>/dev/null | awk 'NR==1{print $2}')
    _eport=${_epraw##*:}
    _eip=${_epraw%:*}; _eip=${_eip#[}; _eip=${_eip%]}
    _sip=$(server_tunnel_ip "$_dt")

    _tpid=""
    if [ -n "$_eip" ] && [ "$_eip" != "(none)" ] && ensure_tcpdump; then
        tcpdump -l -nn -i any "udp and host $_eip and port $_eport" > "$_ulog" 2>/dev/null &
        _tpid=$!
    fi

    printf '\n'
    msg_info "Relatorio sera salvo em: $_log"
    msg_info "Eventos do kernel tambem ficam em: $(kernel_log_source)"
    msg_info "Capturando por ${_dur}s (kernel debug: $([ "$_kdebug" -eq 1 ] && echo sim || echo nao) | tcpdump: $([ -n "$_tpid" ] && echo sim || echo nao))"
    # Janela controlada por relogio: o tempo real da captura nao depende do RTT do ping.
    _pok=0; _ptot=0; _samples=""; _next=5
    _tend=$(( $(date +%s) + _dur ))
    while [ "$(date +%s)" -lt "$_tend" ]; do
        if [ -n "$_sip" ]; then
            _ptot=$((_ptot + 1))
            ping -c1 -W1 "$_sip" >/dev/null 2>&1 && _pok=$((_pok + 1))
        fi
        sleep 1
        _i=$(( $(date +%s) - _t0 ))
        if [ "$_i" -ge "$_next" ]; then
            _next=$((_next + 5))
            _hs=$(wg show "$_dt" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
            _tr=$(wg show "$_dt" transfer 2>/dev/null | awk 'NR==1{print "rx=" $2 "B tx=" $3 "B"}')
            _samples="${_samples}t+${_i}s handshake_epoch=${_hs:-0} ${_tr}
"
            printf '.'
        fi
    done
    printf '\n'

    [ -n "$_tpid" ] && { kill "$_tpid" 2>/dev/null; wait "$_tpid" 2>/dev/null; }
    debug_off
    kernel_log_since "$_t0" "$_dm0" > "$_klog"

    _hs=$(wg show "$_dt" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
    _hsok=0
    [ "${_hs:-0}" -ge "$_t0" ] 2>/dev/null && _hsok=1
    [ "${_hs:-0}" -gt 0 ] && [ $(( $(date +%s) - _hs )) -le 180 ] && _hsok=1

    _analysis=$(analyze_capture "$_klog" "$_ulog" "$_eip" "$_eport" "$_hsok" "$_pok" "$_ptot" "$_sip")
    _pub=$(tr -d ' \t\r\n' < "$WG_DIR/$_dt/publickey")

    {
        printf '=====================================================\n'
        printf ' Relatorio de debug WireGuard | tunel %s | %s\n' "$_dt" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf ' wg-client-manager.sh v%s | duracao %ss | restart=%s\n' "$VERSION" "$_dur" "$_restart"
        printf '=====================================================\n\n'
        printf '== Analise automatica ==\n%s\n\n' "$_analysis"
        printf '== Ambiente ==\n'
        printf 'OS: %s\n' "$( (. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-n/d}") )"
        printf 'Kernel: %s | lockdown: %s | init: %s\n' "$(uname -r)" "$(lockdown_state)" "$(init_system)"
        printf 'wg: %s\n' "$(wg --version 2>/dev/null | head -n1)"
        printf 'Kernel debug: %s | tcpdump: %s\n\n' "$_kdebug" "$([ -n "$_tpid" ] && echo 1 || echo 0)"
        printf '== Configuracao (chaves ocultas) ==\n'
        mask_secrets < "$WG_DIR/$_dt/$_dt.conf"
        printf '\n== Estado WireGuard (final) ==\n'
        wg show "$_dt" 2>&1 | mask_secrets
        printf '\n== Amostras a cada 5s ==\n%s\n' "$_samples"
        printf '== Interface e rotas ==\n'
        ip addr show dev "$_dt" 2>&1
        ip route show dev "$_dt" 2>&1
        if [ -n "$_eip" ] && [ "$_eip" != "(none)" ]; then
            printf 'Rota ate o endpoint: %s\n' "$(ip route get "$_eip" 2>&1 | head -n1)"
            _odev=$(ip route get "$_eip" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
            [ -n "$_odev" ] && printf 'MTU %s: %s | MTU %s: %s\n' "$_odev" \
                "$(cat /sys/class/net/"$_odev"/mtu 2>/dev/null)" "$_dt" "$(cat /sys/class/net/"$_dt"/mtu 2>/dev/null)"
        fi
        printf '\n== Captura UDP (%s:%s) ==\n' "$_eip" "$_eport"
        if [ -s "$_ulog" ]; then cat "$_ulog"; else printf '(sem pacotes ou tcpdump indisponivel)\n'; fi
        printf '\n== Log do kernel (wireguard) ==\n'
        if [ -s "$_klog" ]; then cat "$_klog"; else printf '(vazio: debug indisponivel ou sem eventos)\n'; fi
        printf '\n== Lado servidor (MikroTik RouterOS v7) ==\n'
        printf '/interface wireguard peers print detail where public-key="%s"\n' "$_pub"
        printf '/system logging add topics=wireguard,debug action=memory\n'
        printf '/log print where topics~"wireguard"\n'
        printf '/system logging remove [find topics~"wireguard"]   # desligar ao terminar\n'
    } >> "$_log" 2>&1

    rm -f "$_klog" "$_ulog"
    chmod 600 "$_log"

    printf '\n--- Analise automatica ---\n%s\n\n' "$_analysis"
    msg_ok "Relatorio completo: $_log"
    msg_info "Chaves privadas e PSK ficam ocultas no relatorio. Chaves publicas e IPs aparecem."
}

kernel_log_source() {
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf 'journal do systemd (consulta: journalctl -k | grep -i wireguard)'
    elif dmesg --help 2>&1 | grep -q -- '--follow'; then
        printf 'ring buffer do kernel (consulta: dmesg | grep -i wireguard)'
    elif [ -r /var/log/messages ]; then
        printf '/var/log/messages (consulta: grep -i wireguard /var/log/messages)'
    else
        printf 'ring buffer do kernel (consulta: dmesg | grep -i wireguard)'
    fi
}

print_log_destinations() {
    printf 'Destino dos logs (tudo fica local, nada e enviado para fora da maquina):\n'
    printf '  Relatorios do script : %s/  (pasta 700, arquivos 600)\n' "$LOG_DIR"
    printf '  Eventos do kernel    : %s\n' "$(kernel_log_source)"
}

list_reports() {
    printf '\n--- Relatorios salvos em %s ---\n' "$LOG_DIR"
    if [ -z "$(find "$LOG_DIR" -maxdepth 1 -type f -name '*.log' 2>/dev/null | head -n1)" ]; then
        msg_info "Nenhum relatorio salvo."
        return 0
    fi
    # shellcheck disable=SC2012
    ls -lt "$LOG_DIR"/*.log 2>/dev/null | awk '{printf "  %s %s %s  %8s B  %s\n", $6, $7, $8, $5, $9}'
}

show_last_report() {
    # shellcheck disable=SC2012
    _last=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -n1)
    if [ -z "$_last" ]; then
        msg_info "Nenhum relatorio salvo em $LOG_DIR."
        return 0
    fi
    msg_info "Exibindo: $_last"
    if command -v less >/dev/null 2>&1 && [ -t 1 ]; then less "$_last"; else cat "$_last"; fi
}

debug_live() {
    if ! debug_on; then
        msg_err "Sem debug do kernel nao ha o que acompanhar ao vivo. Use a captura guiada (tcpdump)."
        return 1
    fi
    _lf="/dev/null"
    if confirm "Gravar tambem em arquivo?"; then
        mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
        _lf="$LOG_DIR/live-$(date '+%Y%m%d-%H%M%S').log"
        : > "$_lf" && chmod 600 "$_lf"
    fi
    printf '\n'
    msg_info "Fonte : $(kernel_log_source)"
    if [ "$_lf" != "/dev/null" ]; then
        msg_info "Arquivo: $_lf"
    else
        msg_info "Arquivo: nao gravado (somente tela)"
    fi
    msg_info "Ctrl+C encerra e desativa o debug automaticamente."
    printf '\n'
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        journalctl -kf -n0 -o short-precise | grep -i 'wireguard' | tee -a "$_lf"
    elif dmesg --help 2>&1 | grep -q -- '--follow'; then
        dmesg -w | grep -i 'wireguard' | tee -a "$_lf"
    elif [ -r /var/log/messages ]; then
        tail -n0 -f /var/log/messages | grep -i 'wireguard' | tee -a "$_lf"
    else
        msg_err "Nenhuma fonte de log do kernel com acompanhamento disponivel."
    fi
    debug_off
}

debug_menu() {
    printf '\n--- Debug / Troubleshooting ---\n'
    print_log_destinations
    printf -- '-----------------------------------------------------\n'
    printf ' 1) Captura guiada com relatorio (recomendado)\n'
    printf ' 2) Acompanhar log do kernel ao vivo\n'
    printf ' 3) Listar relatorios salvos\n'
    printf ' 4) Exibir ultimo relatorio\n'
    printf ' 5) Status do debug\n'
    printf ' 6) Forcar desativacao do debug\n'
    printf ' 0) Voltar\n'
    ask _dopt "Opcao"
    case "$_dopt" in
        1) need_wg && debug_capture ;;
        2) debug_live ;;
        3) list_reports ;;
        4) show_last_report ;;
        5) debug_status ;;
        6) debug_force_off ;;
        *) : ;;
    esac
}

# ----------------------------------------------------------------------------
# Menu
# ----------------------------------------------------------------------------
header() {
    clear 2>/dev/null || printf '\033c'
    printf '=====================================================\n'
    printf ' WireGuard Client Manager v%s - EdenCore\n' "$VERSION"
    printf '=====================================================\n'
    if wg_installed; then
        printf ' Status: %sWireGuard instalado%s\n' "$C_G" "$C_N"
    else
        printf ' Status: %sWireGuard NAO instalado (use a opcao 2)%s\n' "$C_R" "$C_N"
    fi
    printf ' Instrutor: Daniel Selbach Figueiró\n'
    printf -- '-----------------------------------------------------\n'
    printf ' 1) Verificar instalacao do WireGuard\n'
    printf ' 2) Instalar WireGuard e dependencias\n'
    printf ' 3) Criar cliente WireGuard\n'
    printf ' 4) Listar clientes\n'
    printf ' 5) Exibir chave publica do cliente (cadastro no servidor)\n'
    printf ' 6) Ativar tunel (com teste de handshake)\n'
    printf ' 7) Desativar tunel\n'
    printf ' 8) Habilitar tunel no boot\n'
    printf ' 9) Status (wg show)\n'
    printf '10) Diagnostico de handshake\n'
    printf '11) Rotacionar par de chaves do cliente\n'
    printf '12) Atualizar PSK (gerada no servidor)\n'
    printf '13) Exibir configuracao (chaves ocultas)\n'
    printf '14) Debug / troubleshooting (log detalhado)\n'
    printf '15) Remover cliente\n'
    printf ' 0) Sair\n'
    printf -- '-----------------------------------------------------\n'
}

need_wg() {
    wg_installed && return 0
    msg_err "WireGuard nao instalado. Use a opcao 2."
    return 1
}

main() {
    require_root
    while :; do
        header
        ask OPT "Opcao"
        case "$OPT" in
            1) check_install ;;
            2) install_wg ;;
            3) create_client ;;
            4) list_clients ;;
            5) select_tunnel T && show_peer_info "$T" ;;
            6) need_wg && select_tunnel T && tunnel_up "$T" ;;
            7) need_wg && select_tunnel T && tunnel_down "$T" ;;
            8) need_wg && select_tunnel T && tunnel_boot "$T" ;;
            9) show_status ;;
           10) need_wg && select_tunnel T && diagnose_tunnel "$T" ;;
           11) need_wg && rotate_keys ;;
           12) need_wg && update_psk ;;
           13) show_conf_masked ;;
           14) debug_menu ;;
           15) need_wg && remove_client ;;
            0) exit 0 ;;
            *) msg_err "Opcao invalida." ;;
        esac
        pause
    done
}

main "$@"
