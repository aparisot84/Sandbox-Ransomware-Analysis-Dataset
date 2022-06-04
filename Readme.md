<h1 align="center"> Sandbox-Ransomware-Analysis-Dataset </h1>

<p align="center"><img src="http://img.shields.io/static/v1?label=STATUS&message=EM%20DESENVOLVIMENTO&color=GREEN&style=for-the-badge"/></p>
<p align="center"><img src="http://img.shields.io/static/v1?label=LANGUAGE&message=PYTHON3&color=YELLOW&style=for-the-badge"/></p>

1 - Decrição do Projeto:

    Este projeto surgiu a partir do meu trabalho de dissertação de mestrado na área de Segurança de Sistemas na Universidade Federal Fluminense.
    Durante o desenvolvimento da pesquisa, tive a necessidade de procurar amostras de ransomware nos repositórios disponíveis na internet, como VirusShare, VirusTtal e malware Bazaar e construir scripts que pudessem automatizar este processo.
    Dentro do escopo geral, cada script realiza uma tarefa específica. Preferi manter dessa maneira, pois achei importante conseguir fazer verificações intermediárias no processo.

2 - Requisitos e limitações:

    Os repositórios utilizados nos scripts são o VirusTotal (VT), MalwareBazzaar (MB) e VirusShare (VS). Para realizar consultas e downloads de amostras, você deve se cadastrar nesses repósitórios e gerar sua chave API. Esta chave que vai te permitir os scripts interagirem com os repositórios. 
    Uma observação que cabe ser feita é que o VirusTotal não permite download de amostras de usuários comuns (mesmo com assinatura acadêmica), apenas usuários vinculados a empresas e que tenham assinatura. Por este motivo precisei utilizar outros repositórios para fazer o download das amostras.
    Atente-se também para as limitações impostas pelos repositórios para interações com suas API (se não houvesse limites, poderiamos causar um DoS):
        
        VirusTotal (Licença Educacional/Pesquisa):
            Request rate => 1000 lookups/min
            Daily quota => 20 K lookups/day
            Monthly quota => 620K lookups/month 

        VirusShare:
            Request rate: 4 requests/min
            Daily Quota: 5,760 requests
            Monthly Quota: 172,800 requests        
    
3 - UInstalação e uso:
    
    Basta clonar o repositório para sua máquina e escolher o malware que deseja procurar (alterando o nome no arquivo 1 - Ransomware HashList Download.py ).
    Recomenda-se manter a estrutura das pastas.  

2 - Scripts:

    1.1 - Ransomware HashList Download:

        A partir do nome de um malware que se deseja conseguir amostras, este script baixa os hashes encontrados no VT e os grava em arquivos distintos para cada malware na pasta 'HashList'.       

    1.2 - HashList Submit Downoad Sample
        
        Este script verifica o conteúdo da pasta HashList e checa os dados no VT para arquivos DLL ou EXE e que tenham o nome do malware na chave 'suggested_threat_label'. Caso atenda os requisitos de formato e nome, o script procura amostras disponíveis no VS e MB e grava na pasta 'ZIP Samples & Download Logs', juntamente com a situação de cada hash: se foi descartado pela extensão e se foi encontrado nos repositórios.

    1.3 -   Dataset Constructs from Json Reports

        Este script transforma os arquivos JSON, produzidos pelo cuckoo sandbox ao executar as análises das amostras, em um dataframe pandas, convertendo os dados selecionados em features para o dataset. 

3 - Dataset
    
    Em desenvolvimento


###########################################################################
olhar banner maker (faz um banner para por no projeto)
olhar shields.io (faz os badges para colocar na página)
awesome readme
markdownify
clairvoyant
##########################################################################
Tem umas explicações e sugestões de templates de readme
https://www.makeareadme.com/

###########################################################################
https://www.freecodecamp.org/news/how-to-write-a-good-readme-file/

Here are some guide questions that will help you out:

    What was your motivation?
    Why did you build this project?
    What problem does it solve?
    What did you learn?
    What makes your project stand out?
    If your project has a lot of features, consider adding a "Features" section and listing them here.

What to Include in your README
1. Project's Title
2. Project Description
    What your application does,
    Why you used the technologies you used,
    Some of the challenges you faced and features you hope to implement in the future.
3. Table of Contents (Optional)
4. How to Install and Run the Project
5. How to Use the Project
6. Include Credits
7. Add a License
8. Badges
9. How to Contribute to the Project
10. Include Tests

Extra points
    Keep it up-to-date
    Pick a language

https://rahuldkjain.github.io/gh-profile-readme-generator/
==================================================================
