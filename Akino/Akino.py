import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import subprocess

# Desenho em laranja
desenho = """
    _    _    _             
   / \\  | | _(_)_ __   ___                                                                                                                                                                                                                 
  / _ \\ | |/ / | '_ \\ / _ \\                                                                                                                                                                                                                
 / ___ \\|   <| | | | | (_) |                                                                                                                                                                                                               
/_/   \\_\\_|\\_\\_|_| |_|\\___/  
"""
# ANSI escape code para laranja
desenho_laranja = "\033[33m" + desenho + "\033[0m"
print(desenho_laranja)

# Desativa os avisos de solicitação insegura (SSL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Solicita a URL do usuário
url = input("\nPor favor, insira a URL: ")

# Comando para executar o WafW00f com a URL fornecida
comando_wafw00f = f"wafw00f {url}"

# Executa o comando e captura a saída
saida_wafw00f = subprocess.check_output(comando_wafw00f, shell=True, text=True)

# Comando para obter os cabeçalhos da URL
response = requests.head(url, verify=False)

# Lista de cabeçalhos de segurança comuns
cabecalhos_de_seguranca = [
    'X-XSS-Protection', 
    'X-Content-Type-Options', 
    'X-Frame-Options', 
    'Strict-Transport-Security', 
    'Content-Security-Policy', 
    'Referrer-Policy', 
    'Permissions-Policy',
    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Opener-Policy'
]

# Verifica se os cabeçalhos de segurança estão presentes na resposta
print("\nCabeçalhos de segurança:")
for cabecalho in cabecalhos_de_seguranca:
    if cabecalho == 'X-Frame-Options':
        if cabecalho in response.headers:
            print(f"{cabecalho}: \033[94mPresente\033[0m")
        else:
            print(f"{cabecalho}: \033[92mNão presente\033[0m")
    elif cabecalho in response.headers:
        print(f"{cabecalho}: \033[92mPresente\033[0m")
    else:
        print(f"{cabecalho}: \033[91mNão presente\033[0m")

# Filtra a linha que contém o resultado do WafW00f
linhas_wafw00f = saida_wafw00f.split('\n')

# Verifica se o WAF foi detectado
waf_detectado = False
for linha in linhas_wafw00f:
    if "No WAF detected by the generic detection" in linha:
        print("\nWAF:\n\033[91mNão possui WAF\033[0m")
        break
    elif "The site" in linha and "is behind" in linha and "WAF." in linha:
        waf_detectado = True
        nome_waf = linha.split("WAF.")[1].strip()
        print(f"\nWAF:\n\033[92mPossui WAF {nome_waf}\033[0m")
        break


