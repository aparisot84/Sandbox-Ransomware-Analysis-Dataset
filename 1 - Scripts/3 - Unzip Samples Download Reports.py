##################################################################################################
#   Este arquivo é responsável por:
#       1 - Deszipar os arquivos das amostras
#       2 - Baixar os relatórios em JSON do cuckoo
#
#########################################################################

import requests
import os
import pyzipper

####################################################################################################
#
#                           TRATAMENTO DE ARQUIVOS E PASTAS
#
####################################################################################################

def list_folder_content(path):

    """Avalia o conteúdo de uma pasta passada como parâmetro e retorna uma lista com o onteúdo de uma pasta """

    content = os.listdir(path)

    return content


def unzip_file(origin_path, destination_path, file):
    """Função que extrai o conteudo de um arquivo zip"""

    print("Descompactando arquivo ZIP")

    with pyzipper.AESZipFile(origin_path + "//" + file) as zf:
        zf.pwd = b"infected"

        zf.extractall(destination_path)

    print("Arquivo descompactao com sucesso!")

    return zf.namelist()[0]

####################################################################################################
#
#                                       CUCKOO
#
####################################################################################################

def tasks_list(url_base, header):
    """Returns the list of tasks stored in the internal Cuckoo database. You can optionally specify a limit of entries to return."""

    url = url_base + "/tasks/list"

    request = requests.get(url, headers=header)

    # data = request.json()

    print(request.text)

def tasks_report(id, url_base, header):
    """Returns the report generated out of the analysis of the task associated with the specified ID. You can optionally specify which report format to return, if none is specified the JSON report will be returned."""

    url = url_base + "/tasks/report/" + str(id)

    request = requests.get(url, headers=header)

    return request


#################################################################################################

url_base = "http://localhost:8090"

header = {"Authorization": "Bearer 1bf0uuFKkg4MC5lB1lTKbA"}

path = '..//3 - Zip Samples & Download Logs//'

final_path = '..//4 - Live Samples//'

#################################################################################################
#
#                                   FUNÇÃO MAIN
#
#################################################################################################

def download_cuckoo_reports():

    """Baixa os relatórios das análises do cuckoo de acordo com a faixa discriminada em range() e salva em um arquivo cujo nome é o hash"""

    for i in range(791, 1453):
        print("Requisitando Relatório")

        data = tasks_report(i, url_base, header)

        print("Relatório Recebido")

        try:
            hash = data.json()["target"]["file"]["sha256"]

            nome_original = data.json()["target"]["file"]["name"]

            #procurar o nome de submissão do arquivo

            path = "..//5 - Cuckoo Reports//"

            print("Nº" + str(i) + " - Gravando relatório da amostra: " + hash)

            print("Nome originado arquivo: " + nome_original)

            with open(path + "//" + str(i) + " - " + hash + ".json", "wb") as f:
                f.write(data.content)

            print("Relatório Gravado")

        except:

            print("Erro na posição " + str(i))


def unzip():

    # na pasta que tem as pastas com os ransomware, entra em cada subpasta e procura os arquivos.zip e descompacta eles na pasta final, criando subpastas com os nomes dos ransomware

    #families = os.listdir(path)

    families = ['revil']

    for name in families:

        path_complete = path + name + "//"

        path_final_complete = final_path + name + "//"

        samples = list_folder_content(path_complete)


        for item in samples:

            if item[-3:] == "zip":

                print(item)

                if not os.path.exists(path_final_complete):

                    os.mkdir(path_final_complete)

                unzipped = unzip_file(path_complete, path_final_complete, item)
                


if __name__ == "__main__":
    #unzip()
    download_cuckoo_reports()
