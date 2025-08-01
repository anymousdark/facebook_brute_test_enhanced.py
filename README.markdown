# Facebook Brute Test Enhanced

`Facebook Brute Test Enhanced` é uma ferramenta educacional em Python projetada para testes éticos de segurança em um ambiente de pentest controlado. Desenvolvida para aprendizado em cibersegurança, a ferramenta permite testar a força de senhas em contas do Facebook (exclusivamente contas próprias do usuário) usando a API de autenticação do Facebook. O script suporta funcionalidades avançadas como proxies, validação de senhas, interface gráfica, e geração de relatórios, sendo ideal para estudantes e profissionais de segurança que desejam entender brute force em um contexto ético.

⚠️ **Aviso Legal**: Esta ferramenta deve ser usada **apenas em contas próprias** em um ambiente de teste autorizado. O uso não autorizado é ilegal e viola os termos de serviço do Facebook. Ative a autenticação de dois fatores (2FA) para proteger suas contas.

## Funcionalidades
- **Teste de Senhas**: Tenta logins com senhas de um arquivo ou personalizadas (ex.: `nome1990`).
- **Validação de Senhas**: Avalia a força das senhas antes do teste.
- **Suporte a Proxies**: Usa proxies HTTP/SOCKS para mascarar o IP.
- **Múltiplos Endpoints**: Alterna entre APIs do Facebook (ex.: `b-graph`, `api`).
- **Interface Gráfica (GUI)**: Interface amigável com `tkinter` para configuração fácil.
- **Modo Seco (Dry Run)**: Simula testes sem enviar requisições reais.
- **Tutorial Interativo**: Explica conceitos de brute force para iniciantes.
- **Relatórios Detalhados**: Gera relatórios em JSON, CSV e banco SQLite.
- **Logging**: Registra todas as tentativas para auditoria.
- **Binário Executável**: Opção para compilar como binário Linux (`/usr/local/bin/facebook_brute_test`).

## Flags de Linha de Comando
- `--gui`: Inicia a interface gráfica.
- `--dry-run`: Executa em modo simulado.
- `--tutorial`: Mostra o tutorial interativo.
- `--uid <ids>`: Define IDs (ex.: `user1@gmail.com,user2@gmail.com`).
- `--password-file <arquivo>`: Especifica o arquivo de senhas.
- `--base-name <nome>`: Gera senhas personalizadas (ex.: `joao1990`).
- `--config <arquivo>`: Usa um arquivo de configuração JSON.
- `--output-dir <diretório>`: Define o diretório de saída.
- `--max-workers <n>`: Configura o número de threads.
- `--no-validate`: Desativa a validação de senhas.

## Pré-requisitos
- Python 3.6+
- Dependências: `pip install requests tqdm tkinter pyinstaller`
- Sistema operacional: Linux (para binário) ou qualquer sistema com Python
- Arquivo de configuração opcional: `config.json`
- Arquivo de senhas opcional: `passwords.txt`

## Instalação
1. Clone o repositório:
   ```bash
   git clone https://github.com/SEU_USUARIO/facebook-brute-test-enhanced.git
   cd facebook-brute-test-enhanced
   ```
2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
3. (Opcional) Crie um arquivo `config.json`:
   ```json
   {
       "api_urls": ["https://b-graph.facebook.com/auth/login"],
       "user_agents": ["Mozilla/5.0 ..."],
       "proxies": [{"http": "http://proxy1:port"}]
   }
   ```

## Uso
- **Modo CLI**:
  ```bash
  python3 facebook_brute_test_enhanced.py --uid myemail@gmail.com --password-file passwords.txt --dry-run
  ```
- **Modo GUI**:
  ```bash
  python3 facebook_brute_test_enhanced.py --gui
  ```
- **Modo Binário (Linux)**:
  Na primeira execução, escolha a opção 2 for criar um binário. Após isso:
  ```bash
  facebook_brute_test --uid myemail@gmail.com
  ```

## Saídas
- Resultados: `output_dir/results.txt`, `output_dir/results.csv`, `output_dir/brute_force.db`
- Relatório: `output_dir/report.json`
- Logs: `output_dir/brute_force.log`

## Exemplo
```bash
python3 facebook_brute_test_enhanced.py --uid myemail@gmail.com --password-file passwords.txt --base-name joao --output-dir ./output
```
- Testa `myemail@gmail.com` com senhas de `passwords.txt` e personalizadas (`joao1990`, etc.), salvando resultados em `./output`.

## Aviso Ético
- **Uso Autorizado**: Use apenas em suas próprias contas em um ambiente de teste controlado.
- **Segurança**: Ative 2FA nas contas testadas para aprender sobre proteção contra brute force.
- **Responsabilidade**: O autor não se responsabiliza por uso indevido. Respeite as leis e os termos de serviço.

## Contribuições
Contribuições são bem-vindas! Envie pull requests ou abra issues para sugerir melhorias, como novas flags ou suporte a outros sistemas operacionais.

## Licença
MIT License. Veja o arquivo `LICENSE` para detalhes.