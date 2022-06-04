##################################################################################################
#   Este Script verifica se os hashes existem nos repositórios VirusShare e MalwareBazzaar,
#   visto que o VirusTotal não permite download de amostras. Além disso, cria arquivos
#   seprardos para cada situação ocorrida durante o processamento dos hashes e faz o download
#   das amostras quando encontradas nos repositórios, quando a extensão for EXE ou DLL.
##################################################################################################

from datetime import datetime
import time
import requests
import json
import os
import pyzipper


def open_hash_file(path, file):

    """Abre o arquivo de hashes no caminho indicado como parâmetro"""
    
    with open(path + file) as file:
    
        content = file.readlines()
    
    return content


def date_converter(timestamp):

    """Converte o timestamp de tempo Unix para data legivel"""

    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')


def save_state(path, hash, family, state):

    """Salva um resumo do estado de determinada submissao, considerando a família e o resultado da chamada na fonte"""

    states = ["descartada", "not found in VS", 'foundinVS.txt', 'desconhecido.txt']

    log_path = path + family + "//"

    if not os.path.exists(log_path):

        os.mkdir(log_path)

    if state in states:

        open(log_path + state + '.txt', 'a').write(hash + '\n')

    else:

        open(log_path + 'desconhecido.txt', 'a').write(hash + '\n')


def unzip_file(path, hash):

    """Funcao que extrai o conteudo de um arquivo zip"""

    with pyzipper.AESZipFile(path + hash + ".zip") as zf:

        zf.pwd = b"infected"

        #my_secrets = zf.extractall(".")  #mantive o original

        zf.extractall(".")  #como que faco pra salvar o arquivo com a hash como nome?????
            
        #print("Sample " + hash + " unpacked.")


def VT_submit_hash(url, hash, header):    

    """Funcao que submete o hash passado como parametro para o VT e entrega a resposta em formato JSON"""

    # Caminho completo do endpoint:https://www.virustotal.com/api/v3/ + files/ + {id}

    url_Complete = url + "files/" + hash

    response = requests.get(url_Complete, headers=header)      

    if "error" in response.text:
        
        return "not found"

    else:     

        data = response.json()    

        return data


def VS_sample_download(url, hash, payload, path, family):

    """Função que baixa e salva a amostra vinda do Virus Share"""

    payload["hash"] = hash

    response = requests.get(url, params=payload)

    log_path = path + family + "//"

    # vai chamar a funcao que salva o arquivo
    
    if response.status_code == 200:

        sample = response.content

        # Chama a funcao que grava sample em arquivo zip

        save_sample(log_path, hash, sample)

        print("Sample downloaded from VS")

    elif ("forbidden" in response.text):

        sample = "forbidden"
    
    else:

        sample = "not found"

    return sample


def MB_sample_download(url, hash, header, data, path, family):

    """Função que baixa e salva a amostra vinda do Malware Bazaar"""

    log_path = path + family + "//"

    data["sha256_hash"] = hash    

    response = requests.post(url, data=data, timeout=15, headers=header, allow_redirects=True)  

    #print(response.status_code) #está dando erro 404

    if ("file_not_found" in response.text):        

        #print(response.status_code)

        sample = "not found"    

    else:

        # Chama a funcao que grava sample em arquivo zip

        sample = response.content        

        save_sample(log_path, hash, sample)

        print("Sample downloaded from MB")

    return sample


def save_sample(path, file_name, content):   #colocar o type aqui pra mudar a pasta de acordo com a família de ransomware

    # peguei esse pedaco de codigo de https://github.com/cocaman/malware-bazaar/blob/master/bazaar_download.py

    open(path + file_name + '.zip', 'wb').write(content)

    pass


def sample_evaluation(reports, family):

    """Funcao que vai avaliar se a amostra e EXE ou DLL para posteriormente ser submetida para analise ou nao do sandbox"""

    report_items = process_reports(reports)     # retorna os itens especificos do report

    if (report_items == "não há dados"):

        return False

    # ANÁLISE DOS ITENS SELECIONADOS DO REPORT

    if (("exe" in report_items["type_extension"].lower()) or ("dll" in report_items["type_extension"].lower()) or ("EXE" in report_items["type_tag"].upper()) or ("dll" in report_items["type_tag"].lower()) or ("exe" in report_items["type_description"].lower()) or ("dll" in report_items["type_description"].lower()) ):

        extension_eval = True

    else:

        extension_eval = False

    # nao estou usando o file para avaliar (nao sei se alguma coisa nao é file)

    if ((family in report_items["malware_names"]) or (family in report_items["suggested_threat_label"].lower())):

        # o metodo lower nao funcionou nas duas partes dese if, nao sei se pode dar problema de descarte de amostras

        name_eval = True

    else:

        name_eval = False

    evaluation = name_eval and extension_eval

    return evaluation


def process_reports(attributes):

    """Cria o dicionário simplificado para análise dos relatorios que foram passados como parametros"""

    attributes_items = {}

    if "data" in attributes:

        if "type_description" in attributes["data"]["attributes"]:

            attributes_items["type_description"] = attributes["data"]["attributes"]["type_description"]   

        else:

            attributes_items["type_description"] = "null"            
        
        if "type_tag" in attributes["data"]["attributes"]:
            
            #na documentação do VT diz que este atributo pode ser usado para filtrar as amostras (tipo de arquivo)

            attributes_items["type_tag"] = attributes["data"]["attributes"]["type_tag"]

        else:

            attributes_items["type_tag"] = "null"    
        
        if ("popular_threat_classification" in attributes["data"]["attributes"]) and "suggested_threat_label" in attributes["data"]["attributes"]["popular_threat_classification"]:
            
            attributes_items["suggested_threat_label"] = attributes["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
            
        else:

            attributes_items["suggested_threat_label"] = "null"

        
        if ("sandbox_verdicts" in attributes["data"]["attributes"]) and ("C2AE" in attributes["data"] ["attributes"]["sandbox_verdicts"]) and ("malware_names" in attributes["data"] ["attributes"]["sandbox_verdicts"]["C2AE"]):            
            
            attributes_items["malware_names"] = attributes["data"] ["attributes"]["sandbox_verdicts"]["C2AE"]["malware_names"]
                        
        else:

            attributes_items["malware_names"] = "null"

        if "type_extension" in attributes["data"]["attributes"]:

            attributes_items["type_extension"] = attributes["data"]["attributes"]["type_extension"]

        else:

            attributes_items["type_extension"] = "null"

        if "type" in attributes["data"]:

            attributes_items["type"] = attributes["data"]["type"]

        else:

            attributes_items["type"] = "null"

        if "creation_date" in attributes["data"]["attributes"]:

            attributes_items["creation_date"] = date_converter(attributes["data"]["attributes"]["creation_date"])
        
        else:

            attributes_items["creation_date"] = "null"
            
        if "last_modification_date" in attributes["data"]["attributes"]:               

            attributes_items["last_modification_date"] = date_converter(attributes["data"]["attributes"]["last_modification_date"])

        if "last_submission_date" in attributes["data"]["attributes"]:

            attributes_items["last_submission_date"] = date_converter(attributes["data"]["attributes"]["last_submission_date"])
        
        if "last_analysis_date" in attributes["data"]["attributes"]:
            
            attributes_items["last_analysis_date"] = date_converter(attributes["data"]["attributes"]["last_analysis_date"])
        
        if "first_submission_date" in attributes["data"]["attributes"]:

            attributes_items["first_submission_date"] = date_converter(attributes["data"]["attributes"]["first_submission_date"])

        return attributes_items

    else:

        return "não há dados"


def print_attributes(attributes):

    """Imprime os atributos de maneira organizada"""

    if "não há dados" in attributes:

        print("não há dados")

    else:

        print("##########################################")

        print(hash)        

        print("type_description => ", attributes["type_description"])
        
        print("type_tag => ", attributes["type_tag"])        

        print("suggested_threat_label => ", attributes["suggested_threat_label"])                    

        print("malware_names => ", attributes["malware_names"])    

        print("type_extension => ", attributes["type_extension"])

        print("type => ", attributes["type"])

        print("creation_date => ", attributes["creation_date"])


######################################################################################
###
###                                 DADOS DAS API
###
######################################################################################

###########################################
#               VIRUSTOTAL
###########################################

VT_Url = "https://www.virustotal.com/api/v3/"

VT_header = {
    "Accept": "application/json",
    "x-apikey": "Your API key here"
}

###########################################
#               MALWAREBAZAAR
###########################################

MB_header = {'API-KEY': 'Your API key here'}

MB_data = {
        'query': 'get_file',
        'sha256_hash': hash,
    } 

MB_url = 'https://mb-api.abuse.ch/api/v1/'

###########################################
#               VIRUSSHARE
###########################################

VS_url = "https://virusshare.com/apiv2/download"

VS_payload = {
    "apikey": "Your API key here",
    "hash": hash
}

######################################################################################
###
###                     DADOS DOS ARQUIVOS LOCAIS
###
######################################################################################

hash_file_path = "..//2 - HashList//"

sample_path = "..//3 - Zip Samples & Download Logs//"

######################################################################################
###
###                     PROGRAMA PRINCIPAL
###
######################################################################################

folder_content = os.listdir(hash_file_path) # lista os arquivos de hash dos ransomware da pasta

contador = 1

print(folder_content) 

for file_names in folder_content:        

    family = file_names[0:-6]      # separa somente o nome da familia do nome dos arquivos

    hashlist = open_hash_file(hash_file_path, file_names)  # carrega a lista do arquivo
    
    for hash in hashlist:

        time.sleep(7)     #tem que ter um tempo senão estoura a cota e dá erro

        hash = hash[:-1]
    
        reports = VT_submit_hash(VT_Url, hash, VT_header)

        report_items = process_reports(reports)

        print("############################")
        print("Contador:", contador)
        print("Família:", family)
        print_attributes(report_items)
        print("############################")

        contador += 1

        if sample_evaluation(reports, family):           

            sample = VS_sample_download(VS_url, hash, VS_payload, sample_path, family)

            if ( sample == "not found"):          

                state = "not found in VS"      

                print("Amostra não encontrada no Virus Share")      

                save_state(sample_path, hash, family, state)

                sample = MB_sample_download(MB_url, hash, MB_header, MB_data, sample_path, family)

                if sample == "not found": 

                    state = "not found in MB"

                    save_state(sample_path, hash, family, state)

                    print("Amostra não encontrada no Malware Bazaar")

            else:

                state = "found in VS"    

                save_state(sample_path, hash, family, sample)

        else:

            #registra em arquivo que a amostra foi rejeitada na avaliacao de relatorio do VT              
            
            print("Amostra não é um arquivo EXE ou DLL e será descartada")

            state = "descartada"

            save_state(sample_path, hash, family, state)
