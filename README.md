# Projeto-integrador-1-semestre
Projeto: Scanner de Vulnerabilidades em Rede

Este projeto implementa um sistema de varredura de portas, identificação de serviços e verificação de vulnerabilidades utilizando Flask, Nmap, Shodan e outras bibliotecas auxiliares.
O objetivo é fornecer uma interface web simples para execução de scans e exibição de resultados em formato estruturado.

1. Requisitos do Sistema

Antes de instalar as dependências do Python, é necessário garantir:

Dependências externas

Python 3.8 ou superior

pip (gerenciador de pacotes Python)

Nmap instalado no sistema

Windows: disponível em https://nmap.org/download.html

Linux (Debian/Ubuntu):

sudo apt install nmap

Acesso API

Chave de API do Shodan
Criar conta e obter em: https://account.shodan.io/

2. Configuração do Ambiente

É recomendado criar um ambiente virtual para isolar as dependências do projeto.

Criar ambiente virtual
python -m venv venv

Ativar ambiente virtual

Windows:

venv\Scripts\activate


Linux/macOS:

source venv/bin/activate

3. Instalação das Dependências Python

Crie ou utilize um arquivo requirements.txt contendo:

Flask
python-nmap
shodan
python-dotenv
requests


Instale tudo com:

pip install -r requirements.txt


Ou instale manualmente:

pip install Flask python-nmap shodan python-dotenv requests

4. Configuração das Variáveis de Ambiente

Crie um arquivo .env na raiz do projeto contendo:

SHODAN_API_KEY=SEU_TOKEN_AQUI


O projeto utiliza python-dotenv para carregar automaticamente essas variáveis.

5. Execução do Projeto

Após instalar as dependências e configurar o ambiente:

python app.py


A aplicação estará disponível por padrão em:

http://127.0.0.1:5000

6. Principais Bibliotecas Utilizadas
Biblioteca	Descrição
Flask	Estrutura da aplicação web e API REST
python-nmap	Wrapper para execução de scanners Nmap
shodan	Integração com API do Shodan para consulta de vulnerabilidades
python-dotenv	Carregamento automático de variáveis de ambiente
requests	Execução de chamadas HTTP
ipaddress	Validação e manipulação de endereços IP
concurrent.futures	Execução paralela de tarefas (ThreadPoolExecutor)
7. Estrutura Recomendada do Projeto
/projeto
│── app.py
│── requirements.txt
│── .env
│── /templates
│     └── index.html
│── /static
      └── css / js / assets
