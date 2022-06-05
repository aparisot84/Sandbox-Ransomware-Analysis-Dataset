##################################################################################################
##################################################################################################

#  TAREFAS:
#
#  1 - ABRIR O ARQUIVO
#  2 - EXTRAIR PARA O HD
#  3 - CARREGAR O ARQUIVO
#  4 - ENVIAR PARA O CUCKOO PARA ANÁLISE (ver os paramâtros análise)
#  5 - APAGAR A AMOSTRA GRAVADA
#  6 - MONITORAR A FINALIZAÇÃO DA ANÁLISE 
#  7 - ENVIAR MAIS OUTRA AMOSTRA (UMA POR VEZ)
#  9 - SALVAR O RELATÓRIO LOCALMENTE
#  
#########################################################################
##
##   Página com boas instruções de como usar o json:
##  realpython.com/python-json/#a-little-vocabulary
##
##  Página com boas dicas de como usar os métodos do requests
##  https://www.geeksforgeeks.org/response-methods-python-requests/
##
##
#########################################################################

from datetime import datetime
import time
import requests
import json
import os
import pyzipper

####################################################################################################
#
#                           TRATAMENTO DE ARQUIVOS E PASTAS
#
####################################################################################################


def list_folder_content(path):
    """Avalia o conteúdo de uma pasta passada como parâmetro e retorna um dicionário com um campo com o conteúdo e um campo indicando se o conteúdo são pastas ou arquivos"""

    content = os.listdir(path)

    return content


def unzip_file(path_origin, path_destination, file):
    """Função que extrai o conteudo de um arquivo zip"""

    print("Descompactando arquivo ZIP para a pasta temporária")

    with pyzipper.AESZipFile(path_origin + "//" + file) as zf:
        zf.pwd = b"infected"

        zf.extractall(path_destination)

    print("Arquivo descompactao corretamente")

    return zf.namelist()[0]

####################################################################################################
#
#                                       CUCKOO
#
####################################################################################################


def submit_file(url_base, header, path, file):
    """ Adiciona um arquivo na lista de tarefas pendentes para ser processsada e analisada. """

    url = url_base + "/tasks/create/file"

    complete_path = path + "//" + file

    print("Iniciando carregamento do arquivo para upload")

    with open(complete_path, "rb") as sample:
        file = {"file": (file, sample)}
        request = requests.post(url, headers=header, files=file)
        if request.status_code == 200:
            print("Task ID: ", request.json()["task_id"], " => enviado!")
        else:
            print("ERRO! Arquivo não enviado", file)
            # gravar numa lista os arquivos com erro de envio   

    return request.json()["task_id"]


def tasks_list(url_base, header):
    """Returns the list of tasks stored in the internal Cuckoo database. You can optionally specify a limit of entries to return."""

    url = url_base + "/tasks/list"

    request = requests.get(url, headers=header)

    # data = request.json()

    print(request.text)


# a função pra monitorar tem que usar 


def task_view(url_base, header, task_id):
    """Retorna os detalhes de uma tarefa com um determinado ID."""

    url = url_base + "tasks/view/" + str(task_id)

    request = requests.get(url, headers=header)

    text = request.text

    print(text)



def tasks_report(id, url_base, header):
    """Returns the report generated out of the analysis of the task associated with the specified ID. You can optionally specify which report format to return, if none is specified the JSON report will be returned."""

    url = url_base + "/tasks/report/" + str(id)

    request = requests.get(url, headers=header)

    return request


def task_summary():
    """Returns a condensed report in JSON format."""

    return


def files_view():
    """Search the analyzed binaries by MD5 hash, SHA256 hash or internal ID (referenced by the tasks details)."""

    return


def cuckoo_status(url_base, header):
    """Returns the basic cuckoo status, including version and tasks overview."""

    # TODO: aqui vai fazer uma consulta ao andamento das tarefas no servidor
    # TODO: usar o threads pra manter isso rodando em loop

    url = url_base + "/cuckoo/status"

    request = requests.get(url, headers=header)

    data = request.json()

    print(" Completed:", data["tasks"]["completed"], "\n",
          "Pending: ", data["tasks"]["pending"], "\n",
          "Reported: ", data["tasks"]["reported"], "\n",
          "Running: ", data["tasks"]["running"], "\n",
          "Total: ", data["tasks"]["total"], "\n",
          )


#################################################################################################

# IMPORTANTE! em cada situação a URL vai ser diferente, portanto cada função deve completar a url base

url_base = "http://localhost:8090"

header = {"Authorization": "Bearer 1bf0uuFKkg4MC5lB1lTKbA"}

path = "//home//ubuntu//Downloads//cuckoo pack//Códigos//Samples"

temp_path = "//home//ubuntu//Documentos//temp"

report_bank_path = "//home//ubuntu//Downloads//cuckoo pack//Códigos//Cuckoo Report Bank"


#################################################################################################
#
#                                   FUNÇÃO MAIN
#
#################################################################################################

def main():
    content = list_folder_content(path)  # dicionario com as pastas dos ransomware

    for folders in content[0:1]:  # * Está travado para passar apenas uma amostra

        path_complete = path + "//" + folders

        samples = list_folder_content(path_complete)

        for items in samples:

            print(items)

            unzipped = unzip_file(path_complete, temp_path, items)

            task_id = submit_file(url_base, header, temp_path, unzipped)

            os.remove(temp_path + "//" + unzipped)  # *remove a amostra enviada ao cuckoo

            status = True

            while status:
                print(task_view(url_base, header, task_id))

            """Usando o /tasks/view/X dá pra interrogar diretamente determinada tarefa usando a ID que a submissão retorna para monitorar o andamento da anális da amostra

            tasks[i]["id"] => retorna a ID de determinada tarefa (tasks é uma lista)

            tasks[i]["status"] => acho que isso dá pra usar pra monitorar o andamento das análises (enquanto nao for reported, aguarda........)

            "failed_analysis"
            "pending"
            "reported"
            "completed"
            """

            # depois que o task view retornar reported, prosseguir com o programa

            break

        # TODO: não esquecer de tentar montar o HD externo na pasta que o cuckoo salva os arquivos

    # cuckoo_status(url_base, header)    #funcionando

    # submit_file(url_base, header, path)    #funcionando



def download_cuckoo_reports():

    """Baixa os relatórios das análises do cuckoo de acordo com a faixa discriminada em range() e salva em um arquivo cujo nome é o hash"""

    # Colocar esta função para executar logo depois que terminar a análise da amostra

    for i in range(1, 187):
        print("Requisitando Relatório")

        data = tasks_report(i, url_base, header)

        print("Relatório Recebido")

        try:
            hash = data.json()["target"]["file"]["sha256"]

            print("Nº" + str(i) + " - Gravando relatório da amostra: " + hash)

            with open(report_bank_path + "//" + str(i) + " - " + hash + ".json", "wb") as f:
                f.write(data.content)

            print("Relatório Gravado")

        except:

            print("Erro na posição " + str(i))


def unzip():
    path_complete = path + "//ransomexx"

    samples = list_folder_content(path_complete)

    for item in samples:
        print(item)

        unzipped = unzip_file(path_complete, temp_path, item)

    return


if __name__ == "__main__":
    # main()
    # unzip()
    download_cuckoo_reports()
