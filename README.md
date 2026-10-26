# Verificador web de FortiGate

Lê os hosts de um XLSX, faz requisições HTTPS nas portas **4443, 4434 e 4461**
e mostra **host, IP, porta e resultado** diretamente no terminal. Não usa ping
nem tenta login.

Execute o programa na conexão de Internet externa que deseja testar. O programa
usa a conexão da própria máquina e não consegue verificar se ela é diferente
da rede normalmente usada para administrar os equipamentos.

## Instalação

Requer Python 3.10 ou superior. No Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

No Windows:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Execução

Confira primeiro o que foi lido, sem fazer conexões:

```sh
.venv/bin/python verificar_fortigate.py caixas.xlsx --listar
```

Faça a verificação:

```sh
.venv/bin/python verificar_fortigate.py caixas.xlsx --origem "Internet externa da filial"
```

No Windows, substitua `.venv/bin/python` por `.venv\Scripts\python.exe`.
O programa exibe o progresso da consulta e, ao terminar, apresenta um resumo
e tabelas com os resultados: interfaces web acessíveis, respostas TLS com
certificado não validado e demais resultados. Cada destino mantém host, IP,
porta, código HTTP quando disponível e o detalhe da verificação.

As cores são automáticas em terminais interativos. Quando a saída é
redirecionada, o conteúdo continua legível, sem sequências de cores ANSI.
Nenhum arquivo de resultado é criado.

## Formato da planilha

Exemplo de estrutura, com endereços reservados apenas para documentação:

| Host | IP |
| --- | --- |
| Filial São Paulo | 192.0.2.10 |
| firewall.exemplo.com | 198.51.100.20 |

São reconhecidos nomes comuns, como `Host`, `Hostname`, `Equipamento`, `IP`,
`Endereço IP`, `IP público`, `WAN IP` e `DNS`. O cabeçalho deve estar nas primeiras
20 linhas. Todas as abas, inclusive ocultas, são examinadas. Abas vazias são
ignoradas; abas com dados e cabeçalho não reconhecido geram aviso no terminal
e no resumo final. Confira esses avisos antes de considerar o inventário completo.

Uma linha pode conter só um IP ou só um nome DNS. Se houver Host e IP, o IP é
o destino da conexão; um Host com nome DNS completo é usado também para SNI
e validação do certificado. Nomes de inventário como `Filial01` são rótulos;
nesse caso a validação usa o IP. DNS com vários IPs produz um resultado para
cada IP e porta. Linhas duplicadas são removidas.

Use valores de texto, sem fórmulas, URLs, portas ou listas de IPs na mesma célula.
Linhas malformadas interrompem a leitura antes das conexões e indicam a aba e
a linha a corrigir. Quando existirem várias colunas de IP, selecione a que deve
ser testada; execute novamente para outro link/WAN:

```sh
.venv/bin/python verificar_fortigate.py caixas.xlsx --aba "Firewalls" --coluna-host "Nome da caixa" --coluna-ip "IP WAN 2" --listar
```

## Interpretação

| Resultado | Significado |
| --- | --- |
| WEB ACESSÍVEL — indícios de FortiGate | O HTTPS respondeu e a página contém marcadores compatíveis com FortiGate. A identidade e o acesso administrativo não estão confirmados. |
| WEB ACESSÍVEL — produto não confirmado | Houve resposta HTTP, inclusive 401, 403 ou redirecionamento, sem evidência suficiente do produto. |
| TLS RESPONDEU — certificado não validado | Há resposta TLS, mas a consulta web ficou inconclusiva por falha de confiança ou nome do certificado. |
| CONEXÃO RECUSADA | O destino recusou a conexão naquele momento. |
| SEM RESPOSTA NO PRAZO | O limite de tempo foi atingido; a causa não foi determinada. |
| FALHA DE DNS / VERIFICAÇÃO INCONCLUSIVA | Não foi possível concluir a consulta; veja o detalhe. |

**Local-in policy não pode ser comprovada apenas de fora.** Uma resposta web
comprova acessibilidade a partir da origem e do horário do teste. Ausência de
resposta também pode decorrer de rota, ACL, NAT ou outro filtro. A confirmação
da regra exige consulta à configuração do FortiGate. Um portal VPN da Fortinet
também não comprova acesso à interface de administração.

A validação TLS permanece ativa. Para uma CA privada conhecida, forneça seu
certificado PEM com `--ca ca-da-empresa.pem`; as CAs padrão continuam disponíveis.
Não há opção para ignorar a validação. Redirecionamentos são registrados sem
seguir o destino. A verificação usa apenas `GET /` e lê uma resposta limitada.

Outras opções: `--timeout 5`, `--tarefas 8` (máximo 64),
`--portas 4443,4434,4461` e `--help`. O timeout limita cada consulta HTTPS;
a resolução DNS usa os prazos do sistema operacional. O código de saída é `0` quando a consulta
e a exibição dos resultados terminam, mesmo com destinos inacessíveis; `2` indica
erro de entrada/configuração e `130`, interrupção pelo operador. Confira as
tabelas finais para saber quais interfaces responderam.

## Validação do projeto

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Os testes usam planilhas temporárias e HTTPS local com certificados de teste;
não fazem consultas a equipamentos reais. Os testes HTTPS precisam do comando
`openssl`, já disponível no ambiente de nuvem preparado.

O XLSX real ainda não foi fornecido neste projeto. Nenhum resultado gerado com
dados sintéticos deve ser usado como avaliação dos equipamentos da empresa.
