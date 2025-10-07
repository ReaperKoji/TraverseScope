<h1 align="center">
  <img src="https://img.shields.io/badge/TraverseScope-%20-purple?style=for-the-badge&logo=python&logoColor=white" width="400">
  <br>
  🧭 TraverseScope 🧠  
</h1>

<p align="center">
  <b>Ferramenta automatizada para detecção e exploração ética de Path Traversal</b><br>
  <i>Projetada para CTFs e pesquisas de Bug Bounty.</i>
</p>

---

### 🌌 Tema: **Cyber Purple**
> Um scanner elegante, simples e eficiente — feito em Python, com foco em segurança ofensiva ética.

<p align="center">
  <img src="https://media.giphy.com/media/xTiTnohtP1l5WfG8Ba/giphy.gif" width="400"/>
</p>

---

## ⚙️ Funcionalidades Principais

- 🚀 Busca automatizada por **Path Traversal / LFI**
- 🧠 Geração e uso de **payloads customizados**
- 🕵️ Varredura de múltiplas URLs ou endpoints
- 📁 Salvamento automático de resultados (`.csv`)
- 🧩 Compatível com **CTFs e testes de segurança**
- 💾 Código 100% em **Python 3**

---

## 🧩 Estrutura do Projeto

TraverseScope/
├── traverse_scope.py # Script principal (gerador + tester local)
├── payloads_path_traversal.txt # Wordlist gerada
├── requirements.txt
├── results/ # Resultados e CSVs
│ └── results_local_test_YYYYMMDD.csv
└── README.md

---

## 📥 Requisitos

- Python 3.11 ou 3.12 (recomendado)
- pip
- Sistema operacional atualizado (Windows 10/11, macOS recente, Linux moderno)

---

## 🛠️ Instalação rápida

1. Instale Python (recomendo 3.12.x).  
- Windows: baixe o instalador do site oficial e marque **Add Python to PATH**.

2. Clone o repositório:

git clone https://github.com/seu-usuario/TraverseScope.git
cd TraverseScope

Crie e ative um ambiente virtual:

# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

---

Instale dependências:

pip install -r requirements.txt


🚦 Aviso de ética e legalidade (LEIA ANTES DE USAR)

⚠️ Uso responsável e autorizado apenas.
Este projeto fornece ferramentas para geração de payloads e testes somente em ambientes que você possui autorização explícita para testar (ex.: sua máquina local, CTFs, labs privados, targets com permissão por escrito em programas de bug bounty).
Não use este software contra sistemas de terceiros sem permissão — isso é ilegal e antiético.

🧭 Uso (exemplos)

O nome do script principal aqui é traverse_scope.py. Adapte se renomear.

1) Gerar payloads (apenas cria a wordlist)

- python traverse_scope.py --gen
# gera: payloads_path_traversal.txt

2) Teste local (APENAS localhost)

python traverse_scope.py --test "http://127.0.0.1:5000/view?file=FUZZ"
# substitui FUZZ por cada payload da wordlist e grava CSV em results/

Se preferir, gere e teste em sequência:

python traverse_scope.py --gen --test "http://127.0.0.1:5000/view?file=FUZZ"

3) Parâmetros úteis

--max-depth N — define profundidade máxima de ../ no gerador (padrão: 8)
--payload-file <arquivo> — path customizado para ler/escrever payloads
--results <arquivo.csv> — arquivo CSV de saída
--rate <segundos> — intervalo entre requisições (mode local)
--timeout <segundos> — timeout de requisições HTTP
--match "root:" "flag{" — strings para procurar nas respostas (heurística)

🔎 Como interpretar resultados

O CSV de saída (ex.: results/results_local_test_YYYYMMDD.csv) contém:

-> payload — payload testado
-> http_status — código HTTP retornado
-> content_length — tamanho do corpo da resposta
-> matched_strings — tags/heurísticas (ex.: contains_root_colon, possible_flag)
-> url — URL final requisitada

Procure por:

-> respostas com http_status 200 e content_length inesperadamente grande;
-> matched_strings indicando root: ou padrões de flag (flag{, FLAG);
-> comportamentos diferenciados (redirects, mensagens de erro específicas).

🧪 Laboratório local sugerido (rápido)

Crie um pequeno servidor Flask vulnerável local para testar:

```
# exemplo mínimo (apenas para lab local, NÃO colocar em produção)
from flask import Flask, request, send_from_directory, abort
app = Flask(__name__)

@app.route('/view')
def view():
    f = request.args.get('file', '')
    # NÃO faça isso em produção - apenas para lab controlado
    try:
        return send_from_directory('/', f)
    except Exception:
        abort(404)

if __name__ == '__main__':
    app.run(port=5000)
```
obs: Após rodar o servidor local, execute o script com --test "http://127.0.0.1:5000/view?file=FUZZ".

💡 Boas práticas para bug bounty & CTF

-> Sempre tenha permissão escrita antes de testar alvos reais.
-> Teste primeiro em ambiente local (container/Docker/VM).
-> Use rate limiting para não causar DoS acidental.
-> Documente e salve provas / logs quando estiver autorizado.
-> Evite causar qualquer alteração destrutiva — prefira leitura (LFI) e análise passiva.

🛠️ Contribuições

Contribuições são bem-vindas — abra issues e PRs para:

-> adicionar novas payloads (SecLists / PayloadsAllTheThings inspired),
-> melhorar heurísticas de detecção,
->integração com ffuf/wfuzz/Burp export formats,
-> adicionar testes automatizados.

Autor

Pedro Galvão (ReaperKoji)
Profissional de Segurança da Informação — focado em tooling, CTFs e bug bounty.
GitHub: https://github.com/ReaperKoji
LinkedIn: https://linkedin.com/in/joao-pedro-eth

## 📜 Licença
MIT License

<p align="center">
  <img src="https://img.shields.io/badge/theme-cyber%20purple-9b59b6?style=for-the-badge">
  <br>
  <b>“Code ethically, hack wisely.”</b> ⚡
</p>
