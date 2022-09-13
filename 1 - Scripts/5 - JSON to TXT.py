import collections
import json
import os

"""
    Transforma os relatórios JSON em arquivos TXT API em ordem de chamada
"""


def read_json(filename: str) -> dict:
    """Carrega o arquivo JSON"""
    
    try:
        with open(filename, "r") as f:
            data = json.loads(f.read())
    except:
        raise Exception(f"Reading {filename} file encountered an error")
    return data


def file_list(path):
    """lista o conteúdo de uma deterinada pasta"""
    
    files = os.listdir(path)
    
    return files


def flatten(d, sep="."):
    """Transforma o json aninhado num dicionário com os nós da árvore concatenados em um único nível, com ponto como separador das chaves do dicionário original"""
    
    # import collections
    
    # obj = {}
    obj = collections.OrderedDict()
    
    def recurse(t, parent_key=""):
        if isinstance(t, list):
            for i in range(len(t)):
                recurse(t[i], parent_key + sep + str(i) if parent_key else str(i))
        elif isinstance(t, dict):
            for k, v in t.items():
                # if v != "NaN": #tentar isso aqui na hora que for rodar
                recurse(v, parent_key + sep + k if parent_key else k)
        else:
            obj[parent_key] = t
    
    recurse(d)
    return obj


def filter_dict2(json_file):
    """
    Filtra o arquivo JSON para concatenar somente as informações escolhidas para compor o dataset. Como os arquivos podem ser muito diferentes, é melhor descartar as entradas indesejadas ao invés de selecionar as entradas desejadas.
    """
    
    filtered_json_file = {}
    
    """
    if ("extracted" in json_file):
        for i in range(len(json_file["extracted"])):
            for key in ["category", 'raw', 'program']:
                filtered_json_file["extracted" + str(i)] = json_file["extracted"][i][key]

    if ("network" in json_file):

        for protocol in ["tcp", 'udp']:
            for i in range(len(json_file["network"][protocol])):
                [json_file["network"][protocol][i].pop(key, "chave: não encontrada") for key in
         ['offset', 'time', 'dport', 'sport']]

        for i in range(len(json_file["network"]["http"])):
            [json_file["network"]["http"][i].pop(key, "chave: não encontrada") for key in
             ['count', 'body', 'version', 'port']]

        for i in range(len(json_file["network"]["dns"])):
            [json_file["network"]["dns"][i].pop(key, "chave: não encontrada") for key in
             ['type', 'answers']]

        [json_file["network"].pop(key, "chave: não encontrada") for key in
         ['dns_servers', 'pcap_sha256', 'sorted_pcap_sha256', 'http_ex']]

        filtered_json_file["network"] = json_file["network"]
        # aqui no final vou inserir os arquivos que fiz filttro

    if ("signatures" in json_file):
        for i in range(len(json_file['signatures'])):
            filtered_json_file['signatures'] = json_file['signatures'][i]['description']

    """
    
    # Talvez seja interessante colocar as chamadas de API na ordem em que foram chamadas e fazer o gram (no artigo do HEAVEN eles fazem referencia a uma limpeza feita em chamadas de API consecutivas iguais, dar uma olhada denovo nessa parada)
    
    if (
            "behavior" in json_file):  # colocar somente o behavior deixa vários arquivos txt sem conteúdo e o tamanho geral dos arquivos continua em 1.1GB, muito grande para ser processado em um dataset
        
        filtered_json_file["behavior_summary"] = json_file["behavior"]["summary"] if (
                "summary" in json_file["behavior"]) else None
        
        # filtered_json_file["behavior_apistats"] = json_file["behavior"]["apistats"] if ("apistats" in json_file["behavior"]) else None     #Tirei pq acaba sendo um monte de lixo numérico
    
    """
    if "memory" in json_file:   #Ao retirar esta seção, os arquivos TXT reduziram de 2.8 GB para 1.1 GB

        for i in range(len(json_file["memory"]["modscan"]["data"])):
            for key in ["kernel_module_file", "kernel_module_name"]:
                filtered_json_file["memory_modscan_" + str(i) + key] = json_file["memory"]["modscan"]["data"][i][key]

        for i in range(len(json_file["memory"]["svcscan"]["data"])):
            for key in ['service_display_name', 'service_binary_path', 'service_name', 'service_type', 'service_state']:
                filtered_json_file["memory_svcscan_" + str(i) + key] = json_file["memory"]["svcscan"]["data"][i][key]

        for i in range(len(json_file["memory"]["privs"]["data"])):
            for key in ['description', 'filename', 'privilege', 'attributes']:
                filtered_json_file["memory_privs_" + str(i) + key] = json_file["memory"]["privs"]["data"][i][key]

        for i in range(len(json_file["memory"]["ldrmodules"]["data"])):
            for key in ['init_full_dll_name', 'mem_full_dll_name', 'dll_mapped_path', 'process_name', 'load_full_dll_name']:
                filtered_json_file["memory_ldrmodules_" + str(i) + key] = json_file["memory"]["ldrmodules"]["data"][i][key]

        #filtered_json_file["memory_deviicetree"] = json_file["memory"]["devicetree"]["data"]

        for i in range(len(json_file["memory"]["handles"]["data"])):
            for key in ['handle_type', 'handle_name']:
                filtered_json_file["memory_handles_" + str(i) + key] = json_file["memory"]["handles"]["data"][i][key]


        filtered_json_file["memory_dlllist"] = json_file["memory"]["dlllist"]["data"]
        filtered_json_file["memory_callbacks"] = json_file["memory"]["callbacks"]["data"]

        for i in range(len(json_file["memory"]["callbacks"]["data"])):
            for key in ['type', 'details', 'module']:
                filtered_json_file["memory_hcallbacks_" + str(i) + key] = json_file["memory"]["callbacks"]["data"][i][key]
    """
    
    """
    if ("strings" in json_file):
        filtered_json_file["strings"] = json_file["strings"]
    """
    
    return filtered_json_file


def save_file(path, filename, content):  # executar isso numa thread
    
    with open(path + filename + ".txt", "a") as f:
        
        buffer = list(content.values())
        
        for item in buffer:
            try:
                f.write(str(item) + '\n')
                # aqui tem um problema de encoding que não sei o que é (e esse problema já tinha dado antes na outra abordagem)
            except:
                pass


def main():
    path = "..//5 - Cuckoo Reports//"  # Esse caminho é só pra carregar os arquivos JSON
    
    print("Obtendo lista de arquivos na pasta", end='')
    json_file_list = file_list(path)
    print("............completo")
    
    cont = 0
    
    for item in sorted(json_file_list):  # [start_file:finish_file]
        
        file_path = path + item
        
        print("Carregando arquivo nº: " + str(cont) + " Nome: " + item, end="")
        json_file = read_json(file_path)  # aqui que tem que entrar o tratamento do json
        print("..............carregado")
        
        print("Aplicando filtros ", end='')
        # filtered_json_file = filter_dict(json_file)
        filtered_json_file = filter_dict2(json_file)
        json_file = None
        print("........finalizado")
        
        print("Transformando JSON aninhado em dicionário", end='')
        flat_json = flatten(filtered_json_file)
        filtered_json_file = None
        print("......finalizado")
        
        print("Tamanho do arquivo: {:.2f}MB".format(os.path.getsize(file_path) / 1000000))
        print("Dicionário com " + str(len(flat_json)) + " linhas")
        
        print("Gravando arquivo em disco", end='')
        save_file("..//7 - TF-IDF//", item[:-5], flat_json)
        # save_file_thread = Thread(target=save_file, args=["..//7 - IF-IDF//", item[:-5], str(flat_json.values())])
        # save_file_thread.start()
        print(" ...........finalizado")
        print(">>>>>Reiniciando<<<<<<")
        
        cont += 1


if __name__ == '__main__':
    main()























