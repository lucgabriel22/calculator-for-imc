# Verificador web de FortiGate

Lê os hosts de um XLSX, consulta HTTPS nas portas **4443, 4434 e 4461**
e mostra **host, IP, porta e resultado** diretamente no terminal. Não usa ping
nem tenta login.

Execute na conexão de Internet externa que deseja testar. O programa usa a
conexão da própria máquina e não determina se ela é diferente da rede usada
normalmente para administrar os equipamentos.

## Requisitos

**Python 3.10 ou superior, apenas com a biblioteca padrão.** A leitura do XLSX
usa os módulos nativos de ZIP e XML; não há dependências externas para instalar.

## Execução

No Linux/macOS:

```sh
python3 verificar_fortigate.py Fortigates.xlsx
```

No Windows:

```powershell
py verificar_fortigate.py Fortigates.xlsx
```

Confira primeiro os alvos, sem resolver DNS nem fazer conexões:

```sh
python3 verificar_fortigate.py Fortigates.xlsx --listar
```

Para registrar na tela a conexão usada no teste:

```sh
python3 verificar_fortigate.py Fortigates.xlsx --origem "Internet externa da filial"
```

O terminal apresenta progresso, resumo e tabelas separadas para interfaces web
acessíveis, respostas TLS com certificado não validado e demais resultados.
Cada destino mantém host, IP, porta, código HTTP quando disponível e detalhe.
As cores são automáticas em terminais interativos; a saída redirecionada
permanece legível, sem sequências ANSI. Nenhum arquivo de resultado é criado.

## Planilha recebida

A estrutura foi inspecionada: o cabeçalho está na linha 6, com as colunas
`Fortigate`, `Grupos`, `IP`, `Local-in-policy` e `SSL VPN`. A identificação de
host e IP é automática para essa estrutura.

Das **877 linhas de inventário**, **804 têm IPs literais válidos**, resultando
em **577 alvos após remover duplicatas**. Outras **73 linhas contêm números
sem os pontos de um IPv4**: 69 têm 12 dígitos e quatro têm 11 dígitos. O programa
não adivinha a separação desses valores; por padrão, interrompe a leitura e
indica as linhas a corrigir, antes de acessar a rede.

Para conferir apenas as linhas válidas, com um aviso para cada linha inválida:

```sh
python3 verificar_fortigate.py Fortigates.xlsx --listar --ignorar-invalidos
```

Após conferir os avisos, a opção também pode ser usada na consulta HTTPS:

```sh
python3 verificar_fortigate.py Fortigates.xlsx --ignorar-invalidos
```

Nesse modo, as 73 linhas inválidas ficam fora da consulta. Corrija-as na
planilha para incluí-las; ignorar erros não torna o inventário completo.
A coluna `Local-in-policy` é informação do inventário, não comprovação da
configuração ou do filtro atual do equipamento.

O arquivo recebido é apenas uma entrada local e não integra o código do
projeto. A inspeção da planilha não realizou consultas aos equipamentos reais.

## Outros formatos de inventário

São reconhecidos cabeçalhos comuns, como `Host`, `Hostname`, `Equipamento`,
`Fortigate`, `IP`, `Endereço IP`, `IP público`, `WAN IP` e `DNS`, nas primeiras
20 linhas. Todas as abas, inclusive ocultas, são examinadas. Abas vazias são
ignoradas; abas com dados e cabeçalho não reconhecido geram aviso. Confira os
avisos antes de considerar o inventário completo.

Uma linha pode conter só IP ou só DNS. Se houver Host e IP, a conexão usa o IP;
um nome DNS completo no campo Host também será usado para SNI e validação
do certificado. Nomes de inventário, como `Filial01`, são rótulos: nesse caso,
a validação usa o endereço. DNS com vários IPs gera um resultado por IP e porta.
Linhas duplicadas são removidas.

Não use fórmulas, URLs, portas ou listas de IPs na mesma célula. Erros de linha
interrompem a leitura por padrão; `--ignorar-invalidos` permite prosseguir com
as válidas, avisando individualmente cada linha descartada. Cabeçalhos
ambíguos exigem seleção explícita. Para escolher aba e colunas:

```sh
python3 verificar_fortigate.py Fortigates.xlsx --aba "Firewalls" --coluna-host "Nome da caixa" --coluna-ip "IP WAN 2" --listar
```

## Interpretação

| Resultado | Significado |
| --- | --- |
| WEB ACESSÍVEL — indícios de FortiGate | O HTTPS respondeu com marcadores compatíveis com FortiGate; identidade e acesso administrativo não confirmados. |
| WEB ACESSÍVEL — produto não confirmado | Houve resposta HTTP, inclusive 401, 403 ou redirecionamento, sem evidência suficiente do produto. |
| TLS RESPONDEU — certificado não validado | O serviço respondeu ao TLS, mas a consulta web ficou inconclusiva por confiança ou nome do certificado. |
| CONEXÃO RECUSADA | O destino recusou a conexão naquele momento. |
| SEM RESPOSTA NO PRAZO | O tempo de consulta acabou; a causa não foi determinada. |
| FALHA DE DNS / VERIFICAÇÃO INCONCLUSIVA | Não foi possível concluir a consulta; veja o detalhe. |

**Local-in policy não pode ser comprovada apenas de fora.** Uma resposta web
comprova acessibilidade a partir da origem e do horário do teste. Ausência de
resposta também pode decorrer de rota, ACL, NAT ou outro filtro. A confirmação
da regra exige consultar a configuração do FortiGate. Um portal VPN da Fortinet
também não comprova acesso à interface de administração.

A validação TLS permanece ativa. Use `--ca ca-da-empresa.pem` para acrescentar
uma CA privada conhecida; as CAs padrão continuam disponíveis. Não há opção
para ignorar a validação. Redirecionamentos são registrados sem seguir o destino.
A consulta faz apenas `GET /` e lê uma resposta limitada.

Outras opções: `--timeout 5`, `--tarefas 8` (máximo 64),
`--portas 4443,4434,4461` e `--help`. O timeout limita cada consulta HTTPS;
a resolução DNS segue os prazos do sistema operacional. O código de saída é
`0` quando a consulta e a exibição terminam, mesmo com destinos inacessíveis;
`2` indica erro de entrada/configuração e `130`, interrupção pelo operador.
Confira as tabelas finais para saber quais interfaces responderam.

## Validação do projeto

```sh
python3 -S -m unittest discover -s tests -v
```

A opção `-S` executa sem carregar pacotes externos. Os testes usam planilhas
temporárias e HTTPS local; não consultam equipamentos reais. Somente os testes
HTTPS precisam do comando `openssl` para criar certificados temporários.
Esse comando não é necessário para executar o aplicativo.
