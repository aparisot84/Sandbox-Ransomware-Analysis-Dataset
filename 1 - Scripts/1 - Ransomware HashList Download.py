###############################################################################
#
# Script que interroga o VirusTotal usando a string atribuída a variavel "query" 
# o nome do malware que se deseja baixar as hashes.
#
# As hashes são gravadas em pasta própria em um arquivo com o nome do malware
#
#   OBS: Necessita de chave de API válida (x-apikey)
##############################################################################

#TODO: AO SUBMETER PARA O GITHUB, APAGAR A CHAVE DA API

import requests
import os

url = "https://www.virustotal.com/api/v3/"
headers = {"x-apikey": "d481057f07194daade825e78d4090e5a5ce2a31bec3bc7fb5e7cdb7cfb72f08a"}

query = "ryuk"
url_query = url + "search?query=" + query + "&limit=300"

path = '..//2 - HashList//'

hashes = []

while True:

    print("Requisitando informações do servidor......", end='')
    response = requests.get(url_query, headers=headers)
    print("finalizado")

    jsonquery = response.json()

    #print(jsonquery.keys())
    for items in jsonquery["data"]:
        temp = items["id"][2:66]
        if temp not in hashes:
            hashes.append(temp + "\n")
            print(temp)

    if "next" not in jsonquery["links"]:
        print("Não há mais informações para carregar sobre este malware")
        break
    else:
        url_query = jsonquery["links"]["next"]


print("Gravando as hashes em disco........", end='')
with open(path + query + "hashes", "a") as f:
    f.writelines(hashes)
print("finalizado")







