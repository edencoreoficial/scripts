# Instalação do Winbox 4 via Script
## winbox4-setup.fedora.sh

Instalador do **MikroTik WinBox 4** para Fedora Linux. Baixa a versão mais recente direto do site oficial da MikroTik, instala no diretório do usuário e cria o atalho no menu de aplicativos.

Baseado em [thiagojolv/winbox-fedora](https://github.com/thiagojolv/winbox-fedora), reescrito com foco em segurança e sem atualizar o sistema.

## Diferenças em relação ao script original

- **Não executa `dnf upgrade`.** Nenhum pacote do sistema é atualizado, incluindo o kernel. Útil para quem mantém uma versão específica de kernel fixada.
- Instala apenas as dependências que faltarem (`curl` e `unzip`), com `--setopt=excludepkgs='kernel*'` para impedir que qualquer pacote de kernel entre como dependência.
- Busca o link em `https://mikrotik.com/download/winbox` e só aceita URLs no formato `https://download.mikrotik.com/routeros/winbox/<versão>/WinBox_Linux.zip`.
- Exibe o SHA256 do arquivo baixado para conferência.
- Usa diretório temporário seguro (`mktemp -d`), removido automaticamente ao final.
- Aceita diretório de instalação personalizado, e o atalho `.desktop` e a desinstalação respeitam esse diretório.
- Desinstalação com trava que impede apagar `$HOME`, `/` ou caminho vazio.
- `set -euo pipefail`: o script para no primeiro erro em vez de seguir em estado inconsistente.

## Requisitos

- Fedora Linux, arquitetura x86_64 (a MikroTik só publica o WinBox para Linux em 64-bit x86)
- Acesso a `sudo`, apenas se `curl` ou `unzip` não estiverem instalados
- Ambiente gráfico com suporte a atalhos freedesktop (GNOME, KDE, XFCE etc.)

## Instalação

```bash
chmod +x winbox4-setup.fedora.sh
./winbox4-setup.fedora.sh
```

O WinBox é instalado em `~/.winbox` e aparece no menu de aplicativos como **WinBox**.

Para instalar em outro diretório, passe o caminho como argumento:

```bash
./winbox4-setup.fedora.sh ~/Apps/winbox
```

## Atualização

Rode o script novamente. Ele baixa a versão mais recente e sobrescreve os arquivos no mesmo diretório.

## Desinstalação

```bash
./winbox4-setup.fedora.sh --uninstall
```

O script pede confirmação e remove o diretório de instalação, o atalho `.desktop` e o arquivo de controle.

## Arquivos criados

| Caminho | Função |
|---|---|
| `~/.winbox/` (ou o diretório escolhido) | Binário e arquivos do WinBox |
| `~/.local/share/applications/winbox.desktop` | Atalho no menu de aplicativos |
| `~/.config/winbox-install-dir` | Registra o diretório usado, para a desinstalação |

## Solução de problemas

**`ERRO: link do WinBox_Linux.zip nao encontrado`**
A MikroTik alterou a página de download. Enquanto o script não for ajustado, instale manualmente pegando o link em `https://mikrotik.com/download/winbox`:

```bash
curl -fLO https://download.mikrotik.com/routeros/winbox/<versão>/WinBox_Linux.zip
unzip -o WinBox_Linux.zip -d ~/.winbox && chmod +x ~/.winbox/WinBox
```

**O atalho não aparece no menu**
Encerre a sessão e entre novamente, ou execute:

```bash
update-desktop-database ~/.local/share/applications
```

## Opções

| Opção | Descrição |
|---|---|
| *(sem argumento)* | Instala em `~/.winbox` |
| `DIRETORIO` | Instala no diretório informado |
| `--uninstall` | Remove o WinBox |
| `-h`, `--help` | Mostra a ajuda |
