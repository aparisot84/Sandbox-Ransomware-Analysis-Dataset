<h1 align="center"> Sandbox-Ransomware-Analysis-Dataset </h1>

<div align="center">
<p align="center"><img src="http://img.shields.io/static/v1?label=STATUS&message=EM%20DESENVOLVIMENTO&color=GREEN&style=for-the-badge"/></p>
<p align="center"><img src="http://img.shields.io/static/v1?label=LANGUAGE&message=PYTHON3&color=YELLOW&style=for-the-badge"/></p>
</div>

DISCLAIMER: Os scripts contidos neste reporitório fazem o download de malware direto para a sua máquina. A sintaxe das pastas (com //) é a do linux e os arquivos baixados são apenas DLL ou EXE.
Se você não tem plena ciência do que está fazendo, não execute os scripts, pois voce corre o risco de ter seus arquivos criptografados e não me responsabilizo se isso acontecer.

1 - Decrição do Projeto:

Este projeto surgiu a partir do meu trabalho de dissertação de mestrado na área de Segurança de Sistemas na Universidade Federal Fluminense.
Durante o desenvolvimento da pesquisa, tive a necessidade de procurar amostras de ransomware nos <br>repositórios diponíveis na internet, como VirusShare, VirusTtal e malware Bazaar e construir scripts <br>que pudessem automatizar este processo.

Dentro do escopo geral, cada script realiza uma tarefa específica. Preferi manter dessa maneira, pois achei importante conseguir fazer verificações intermediárias no processo.

2 - Requisitos e limitações:

Os repositórios utilizados nos scripts são o VirusTotal (VT), MalwareBazzaar (MB) e VirusShare (VS). <br>Para realizar consultas e downloads de amostras, você deve se cadastrar nesses repósitórios e gerar sua <br>chave API. Esta chave que vai te permitir os scripts interagirem com os repositórios. 

Uma observação que cabe ser feita é que o VirusTotal não permite download de amostras de usuários <br> comuns (mesmo com assinatura acadêmica), apenas usuários vinculados a empresas e que tenham assinatura. Por este motivo precisei utilizar outros repositórios para fazer o download das amostras.
Atente-se também para as limitações impostas pelos repositórios para interações com suas API (se <br> não houvesse limites, poderiamos causar um DoS):
        
        VirusTotal (Licença Educacional/Pesquisa):
            Request rate => 1000 lookups/min
            Daily quota => 20 K lookups/day
            Monthly quota => 620K lookups/month 

        VirusShare:
            Request rate: 4 requests/min
            Daily Quota: 5,760 requests
            Monthly Quota: 172,800 requests        
    
3 - Instalação e uso:
    
Basta clonar o repositório para sua máquina e escolher o malware que deseja procurar (alterando o <br> nome no arquivo 1 - Ransomware HashList Download.py ).
Recomenda-se manter a estrutura das pastas.  
Para conseguir reproduzir meus passos até o final, você necessitará ter o cuckoo sandbox funcionando. O arquivo 'Guia Cuckoo.txt' é um passo a passo para instalação e execução do cuckoo que consegui aqui e  adicionei alguns passos extras que necessitei ao realizar este trabalho.

4 - Scripts:

4.1 - Ransomware HashList Download:

A partir do nome de um malware que se deseja conseguir amostras, este script baixa os hashes  encontrados no VT e os grava em arquivos distintos para cada malware na pasta 'HashList'.       

4.2 - HashList Submit Downoad Sample
        
Este script verifica o conteúdo da pasta HashList e checa os dados no VT para arquivos DLL ou EXE e que tenham o nome do malware na chave 'suggested_threat_label'. Caso atenda os requisitos de formato e  nome, o script procura amostras disponíveis no VS e MB e grava na pasta 'ZIP Samples & Download Logs',  juntamente com a situação de cada hash: se foi descartado pela extensão ser diferente e/ou se foi e encontrado (ou não) nos repositórios.

4.3 - XXXXXXXXXXXXX

Arquivo que deszipa as amostras de
Arquivo que baixa os relatórios em JSON do cuckoo (ver se dá pra colocar junto com o script que <br> já baixa as amostras)

4.3 -   Dataset Constructs from Json Reports

Este script transforma os arquivos JSON, produzidos pelo cuckoo sandbox ao executar as análises <br> das amostras, em um dataframe pandas, convertendo os dados selecionados em features para o dataset. 

5 - Dataset
    
Em desenvolvimento.

