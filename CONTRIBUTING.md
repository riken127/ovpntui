# Contribuir para o ovpntui

Obrigado por quereres contribuir. Issues e pull requests são bem-vindas para
correções, melhorias de usabilidade e compatibilidade com perfis OpenVPN.

## Preparar o ambiente

- Go 1.24 ou superior e `make` para compilar.
- OpenVPN 2.x para testar ligações reais. O build e os testes existentes não
  precisam de privilégios de administrador nem alteram as rotas do sistema.
- `golangci-lint` é necessário apenas para `make lint`.

```sh
git clone https://github.com/riken127/ovpntui.git
cd ovpntui
make check
./bin/ovpntui --version
```

`make check` verifica formatação, executa `go vet`, os testes existentes e o
build. `make race` executa os mesmos testes com o detetor de concorrência.
`make fmt` formata os ficheiros Go. Para experimentar uma alteração local,
`make install` instala os dois binários em `~/.local/bin`.

## Estrutura do projeto

- `cmd/ovpntui`: CLI e arranque da interface.
- `cmd/ovpntuid`: daemon por utilizador.
- `internal/tui`: interface de terminal.
- `internal/daemon`: protocolo local, arranque e ciclo de vida do daemon.
- `internal/openvpn`: processo OpenVPN, management socket e estados da sessão.
- `internal/profile`: importação, validação e armazenamento dos perfis.
- `internal/credentials`: integração opcional com Secret Service.

O daemon corre com o utilizador normal e eleva apenas o OpenVPN. A validação de
perfis importados e as permissões das diretorias privadas são limites de
segurança: explica qualquer alteração a esses comportamentos na pull request.

## Abrir uma issue ou pull request

1. Pesquisa issues e pull requests existentes antes de abrir uma nova.
2. Descreve o comportamento observado, o esperado e como reproduzir. Indica o
   sistema operativo, a versão do Go e a versão do OpenVPN.
3. Mantém a alteração focada e explica no PR o que mudou e como foi validado.
4. Executa `make check` antes de enviar. Para alterações ao supervisor ou ao
   protocolo, executa também `make race`.

Os testes de integração usam um OpenVPN simulado. Para alterações de rotas ou
desligamento, descreve também a validação manual numa VPN de teste e o estado
das rotas antes e depois; os testes não criam um túnel real.

Nunca coloques perfis reais, chaves, passwords, URLs de SSO com tokens ou logs
com dados sensíveis numa issue ou pull request. Remove esses dados dos exemplos
antes de os publicar.
