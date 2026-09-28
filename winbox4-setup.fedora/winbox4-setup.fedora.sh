#!/usr/bin/env bash
#
# winbox-setup.sh - Instala o MikroTik WinBox 4 no Fedora
# Baseado em: https://github.com/thiagojolv/winbox-fedora
#
# NAO executa dnf upgrade: nenhum pacote do sistema (kernel incluso) e atualizado.
# Instala apenas o que falta (unzip) com --setopt para ignorar pacotes de kernel.
#
# Uso:
#   ./winbox-setup.sh              instala em ~/.winbox
#   ./winbox-setup.sh /outro/dir   instala no diretorio informado
#   ./winbox-setup.sh --uninstall  remove
#
set -euo pipefail

DOWNLOAD_PAGE="https://mikrotik.com/download/winbox"
TMP_DIR=""                                       # global: o trap EXIT precisa enxergar
DEFAULT_DIR="$HOME/.winbox"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/winbox.desktop"
MARKER_FILE="$HOME/.config/winbox-install-dir"   # guarda o diretorio usado, para o uninstall

usage() {
    cat <<EOF
Uso: $0 [DIRETORIO] | --uninstall | -h
Instala o WinBox 4 (ultima versao) a partir de $DOWNLOAD_PAGE.
  DIRETORIO      destino da instalacao (padrao: $DEFAULT_DIR)
  --uninstall    remove o WinBox
  -h, --help     mostra esta ajuda
EOF
}

ensure_deps() {
    local missing=()
    for cmd in curl unzip; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if (( ${#missing[@]} )); then
        echo "Instalando dependencias: ${missing[*]}"
        # excludepkgs impede que o dnf puxe qualquer pacote de kernel como dependencia
        sudo dnf -y install --setopt=excludepkgs='kernel*' "${missing[@]}"
    fi
}

get_download_url() {
    local url
    # Regex ja restringe ao dominio oficial e ao formato .../winbox/<versao>/WinBox_Linux.zip
    url="$(curl -fsSL "$DOWNLOAD_PAGE" \
        | grep -oE 'https://download\.mikrotik\.com/routeros/winbox/[0-9][0-9.]*/WinBox_Linux\.zip' \
        | head -n1 || true)"
    if [[ -z "$url" ]]; then
        echo "ERRO: link do WinBox_Linux.zip nao encontrado em $DOWNLOAD_PAGE" >&2
        return 1
    fi
    echo "$url"
}

install_winbox() {
    local dest="${1:-$DEFAULT_DIR}"
    dest="$(realpath -m "$dest")"

    ensure_deps

    TMP_DIR="$(mktemp -d)"
    trap '[[ -n "${TMP_DIR:-}" ]] && rm -rf -- "$TMP_DIR"' EXIT

    local url
    url="$(get_download_url)" || exit 1
    echo "Baixando: $url"
    curl -fL --proto '=https' --tlsv1.2 -o "$TMP_DIR/WinBox_Linux.zip" "$url"

    echo "SHA256 do arquivo baixado:"
    sha256sum "$TMP_DIR/WinBox_Linux.zip"

    mkdir -p "$dest"
    unzip -oq "$TMP_DIR/WinBox_Linux.zip" -d "$dest"
    chmod +x "$dest/WinBox"

    mkdir -p "$DESKTOP_DIR" "$(dirname "$MARKER_FILE")"
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=WinBox
GenericName=Configuration tool for RouterOS
Comment=Configuration tool for RouterOS
Exec="$dest/WinBox"
Icon=$dest/assets/img/winbox.png
Terminal=false
Type=Application
StartupNotify=true
Categories=Network;RemoteAccess;
Keywords=winbox;mikrotik;
EOF
    echo "$dest" > "$MARKER_FILE"

    command -v update-desktop-database >/dev/null && update-desktop-database "$DESKTOP_DIR" || true
    echo "WinBox instalado em: $dest"
}

uninstall_winbox() {
    local dest="$DEFAULT_DIR"
    [[ -f "$MARKER_FILE" ]] && dest="$(<"$MARKER_FILE")"

    # Trava de seguranca: nunca apagar HOME, raiz ou caminho vazio
    if [[ -z "$dest" || "$dest" == "/" || "$dest" == "$HOME" ]]; then
        echo "ERRO: diretorio de instalacao invalido: '$dest'" >&2
        exit 1
    fi
    if [[ ! -x "$dest/WinBox" ]]; then
        echo "WinBox nao encontrado em $dest. Nada a remover."
        exit 0
    fi

    read -rp "Remover WinBox de $dest? (s/N): " ans
    [[ "$ans" =~ ^[sSyY]$ ]] || { echo "Cancelado."; exit 0; }

    rm -rf -- "$dest"
    rm -f -- "$DESKTOP_FILE" "$MARKER_FILE"
    command -v update-desktop-database >/dev/null && update-desktop-database "$DESKTOP_DIR" || true
    echo "WinBox removido."
}

case "${1:-}" in
    -h|--help)   usage ;;
    --uninstall) uninstall_winbox ;;
    *)           install_winbox "${1:-}" ;;
esac
