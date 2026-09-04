# ovpntui

`ovpntui` é um gestor TUI leve para perfis OpenVPN em Linux. A interface usa
[Bubble Tea](https://github.com/charmbracelet/bubbletea),
[Bubbles](https://github.com/charmbracelet/bubbles) e
[Lip Gloss](https://github.com/charmbracelet/lipgloss); as ligações são sempre
feitas pelo binário `openvpn` instalado no sistema.

## Funcionalidades

- Importa `.ovpn`, certificados, chaves, CRLs e ficheiros TLS externos para uma
  diretoria privada e reescreve as referências do perfil.
- Preserva certificados e chaves inline.
- Lista, renomeia e elimina perfis persistentes.
- Liga, desliga e supervisiona um processo por perfil através de um daemon de
  utilizador persistente (`ovpntuid`). Fechar e reabrir a TUI não interrompe a
  VPN nem perde o estado.
- Mostra estado, duração, PID, interface e IP atribuído quando o OpenVPN os
  publica nos logs.
- Apresenta logs da sessão na TUI e guarda uma cópia persistente.
- Pede username/password numa caixa mascarada. As passwords nunca são guardadas
  nos ficheiros da aplicação; opcionalmente usa o keyring Secret Service.
- Suporta WebAuth/OIDC SSO (incluindo Zitadel) através do management protocol do
  OpenVPN: abre o browser, mantém o fluxo de autenticação no daemon e nunca
  persiste o URL/token de autorização.
- Deteta saídas inesperadas e encerra processos filhos ao desligar um perfil ou
  ao terminar explicitamente o daemon.

## Dependências e instalação

Requer Linux, Go 1.24+ para compilar e OpenVPN 2.x em runtime. `sudo` ou
`pkexec` é recomendado. Para guardar credenciais também é necessário
`secret-tool` (normalmente fornecido por `libsecret-tools`).

Em Debian/Ubuntu:

```sh
sudo apt install openvpn libsecret-tools
go install github.com/riken127/ovpntui/cmd/ovpntui@latest
go install github.com/riken127/ovpntui/cmd/ovpntuid@latest
```

Para compilar o checkout (os dois binários são necessários e devem permanecer
na mesma diretoria):

```sh
make build
./bin/ovpntui
```

Também há arquivos de release `linux/amd64` e `linux/arm64` produzidos pelo
GoReleaser. Copia o binário para um diretório no `PATH`.

## Utilização

| Tecla | Ação |
|---|---|
| `i` | importar um `.ovpn` pelo caminho local |
| `enter` | ligar ou desligar o perfil selecionado |
| `o` | ligar através de Browser SSO/OIDC |
| `l` | abrir os logs da sessão |
| `r` | alterar o nome |
| `d` | eliminar, com confirmação |
| `/` | filtrar a lista |
| `q` | fechar apenas a TUI; as VPNs continuam ligadas |

No formulário de credenciais VPN, `Enter` liga sem guardar e `Ctrl+S` guarda o par
username/password no Secret Service antes de ligar. O ficheiro de credenciais
necessário ao OpenVPN só existe durante a ligação, em modo `0600`, e é removido
no fim.

### Zitadel / Browser SSO

Seleciona o perfil e prime `o`; em alternativa, abre o formulário com `Enter` e
prime `Ctrl+O` (o username é opcional nesse fluxo). Depois de autorizar o `sudo`,
o browser abre a página fornecida pelo servidor. Conclui o login no Zitadel e
volta à TUI. O estado mostra `waiting for browser SSO` até a autorização acabar.

Esta integração requer OpenVPN 2.5 ou posterior e um servidor configurado para
WebAuth/OIDC. O cliente anuncia `IV_SSO=webauth,openurl` e recebe `AUTH_PENDING`
e `WEB_AUTH` por um Unix socket privado. Só são abertos URLs `https://`; o URL
com o token de utilização única existe apenas em memória e não é escrito nos
logs. As credenciais placeholder exigidas pelo protocolo OpenVPN também existem
apenas no ficheiro runtime `0600` e são removidas no fim da sessão.

Referências de interoperabilidade: [OpenVPN management interface](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
e [openvpn-auth-oauth2 com Zitadel](https://github.com/jkroepke/openvpn-auth-oauth2/wiki/OpenVPN).

Quando `sudo` não tiver uma autorização válida no contexto do daemon, a TUI
abre um segundo formulário mascarado para a password de administrador. Essa
password é enviada apenas pelo socket privado, usada uma vez por `sudo -S -v`,
apagada da mensagem de arranque e nunca guardada, escrita em logs ou colocada
nos argumentos do processo.

Opções de arranque:

```text
--privilege=auto|sudo|pkexec|none
--openvpn=/caminho/para/openvpn
--stop-daemon
--version
```

Na primeira execução, `ovpntui` inicia automaticamente `ovpntuid` em background.
O daemon é executado pela conta normal do utilizador e comunica através de um
Unix socket `0600`. Se voltares a abrir a TUI, ela recupera os estados e logs das
sessões que o daemon continua a supervisionar.

Cada processo OpenVPN tem ainda um management Unix socket privado, criado dentro
da diretoria runtime `0700` e acessível apenas ao utilizador. É este canal que
liberta o arranque (`management-hold`) e recebe eventos SSO; não é exposto em TCP.

Para desligar todas as VPNs e terminar explicitamente o daemon:

```sh
ovpntui --stop-daemon
```

## Permissões

Não executes `ovpntui` como root; a aplicação recusa fazê-lo. Apenas o comando
OpenVPN é elevado, sem shell e com cada argumento separado.

O modo predefinido `auto` segue esta ordem:

1. usa `sudo -n` se já existir uma autorização em cache;
2. numa sessão gráfica, usa `pkexec` se o `sudo` precisar de autenticação;
3. se não houver `pkexec`, tenta `sudo -n` e apresenta uma mensagem útil.

Em terminais sem agente gráfico podes autenticar antecipadamente:

```sh
sudo -v
ovpntui --privilege=sudo
```

Se a cache `sudo` estiver associada a outro terminal — comportamento comum no
macOS — a aplicação pede a password de administrador na própria TUI.

`--privilege=none` é indicado quando o binário OpenVPN já tem as capabilities
necessárias ou quando se usa uma configuração que não requer elevação. Conceder
capabilities diretamente a binários tem implicações de segurança e não é feito
automaticamente por esta aplicação.

Ao desligar um perfil, `ovpntuid` envia `SIGINT` ao grupo do helper/OpenVPN e
espera até oito segundos antes de usar `SIGKILL`. Esta abordagem permite ao
OpenVPN remover rotas e interfaces normalmente e faz com que `sudo`/`pkexec`
encaminhem o sinal para o filho elevado. `SIGTERM`, `SIGHUP` ou `SIGINT` enviados
ao daemon desligam todas as sessões de forma controlada.

Os pedidos de arranque contêm apenas o ID de um perfil persistido. O daemon volta
a carregar e validar a cópia privada antes de a passar ao OpenVPN. Diretivas que
podem executar código ou escrever arbitrariamente como root — scripts, plugins,
includes, management sockets, logs definidos pelo perfil e modo daemon — são
rejeitadas na importação e novamente na execução.

## Dados e segurança

São seguidas as diretórias XDG:

- `$XDG_CONFIG_HOME/ovpntui/profiles/<id>/`: perfil e assets importados;
- `$XDG_RUNTIME_DIR/ovpntui/`: socket do daemon, lock, PID e credenciais temporárias;
- `$XDG_STATE_HOME/ovpntui/logs/`: logs persistentes.

Se `XDG_RUNTIME_DIR` não estiver definido, é usada uma diretoria privada
`$TMPDIR/ovpntui-<uid>/`. Diretorias usam `0700`; configurações, assets,
metadados, logs e credenciais temporárias usam `0600`. Durante a importação,
referências como `ca`, `cert`, `key`, `pkcs12`, `dh`, `tls-auth`, `tls-crypt`,
`tls-crypt-v2`, `crl-verify`, `extra-certs` e `secret` são copiadas. Um
`auth-user-pass` que aponte para um ficheiro, ou um bloco inline com credenciais,
é substituído por recolha interativa para não importar passwords em claro.

## Troubleshooting

- **`openvpn is not installed`**: instala o pacote OpenVPN ou usa
  `--openvpn=/caminho/absoluto`.
- **autorização sudo necessária**: introduz a password de administrador no
  formulário mascarado. Se for rejeitada repetidamente, confirma a política
  sudo ou seleciona `--privilege=pkexec` numa sessão gráfica Linux.
- **`ovpntuid is not installed`**: instala/copia `ovpntuid` para a mesma diretoria
  de `ovpntui` ou para outro diretório no `PATH`.
- **socket path is too long**: define `XDG_RUNTIME_DIR` para uma diretoria privada
  mais curta; Unix sockets têm limites de caminho baixos em algumas plataformas.
- **perfil rejeitado por segurança**: remove diretivas de scripts, plugins,
  includes, logging/management ou daemonização. Elas impediriam supervisão segura
  de um OpenVPN elevado.
- **`permission denied` / falha ao criar TUN**: confirma a política de sudo/polkit
  e a disponibilidade de `/dev/net/tun`.
- **certificado ou ficheiro em falta**: volta a importar a partir de uma pasta que
  contenha todas as referências relativas. O erro indica a diretiva e o caminho.
- **credenciais não são guardadas**: instala `secret-tool` e confirma que existe
  uma sessão Secret Service desbloqueada. Ainda é possível ligar sem guardar.
- **falha de autenticação ou TLS**: abre os logs com `l`; o caminho do log
  persistente também é mostrado nessa vista.
- **`AUTH_FAILED` ao usar username/password num perfil Zitadel**: inicia o
  perfil com `o`/`Ctrl+O`. Se continuar a não surgir `waiting for browser SSO`,
  o servidor não está a devolver `AUTH_PENDING`/`WEB_AUTH`; confirma a
  configuração OIDC/WebAuth no servidor.
- **o browser não abre**: a status bar mostra o URL para abertura manual.
  Confirma que `xdg-open` está instalado e que o URL fornecido pelo servidor usa
  HTTPS.

## Desenvolvimento

```sh
make fmt
make test
make race
make lint
```

Os testes de integração usam um processo OpenVPN falso e não criam interfaces,
rotas ou ligações reais. Também testam o protocolo Unix socket, reabertura do
cliente, lock de instância única e limpeza de credenciais runtime abandonadas. A
CI executa build, race tests e `golangci-lint`. Tags `v*` publicam `ovpntui` e
`ovpntuid` para Linux através de GoReleaser.

## Licença

MIT — consulta [LICENSE](LICENSE).
