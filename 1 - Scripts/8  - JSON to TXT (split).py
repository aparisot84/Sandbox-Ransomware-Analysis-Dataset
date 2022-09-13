import collections
import json
import os

"""
    Transforma os relatórios JSON em arquivos TXT com os termos separados por seção e suas respectivas quantidades, em ordem decrescente.
"""


def read_json(filename: str) -> dict:
    """Carrega o arquivo JSON"""
    
    try:
        with open(filename, "r") as f:
            data = json.loads(f.read())
    except:
        raise Exception(f"Reading {filename} file encountered an error")
    return data


def file_list(path: str) -> list:
    """lista o conteúdo de uma deterinada pasta"""
    
    files = os.listdir(path)
    return files


def flatten(d: dict, sep=".") -> collections.OrderedDict:
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


def filter_dict(json_file: dict) -> dict:
    """
    Filtra o arquivo JSON para concatenar somente as informações escolhidas para compor o dataset. Como os arquivos podem ser muito diferentes, é melhor descartar as entradas indesejadas ao invés de selecionar as entradas desejadas.
    """

    # AGORA QUE VOU FAZER CADA SEÇÃO SEPARADA, POSSO SER MAIS PERMISSIVO COM A QUANTIDADE DE DADOS QUE VOU DEIXAR PASSAR PARA O TF
    
    filtered_json_file = {'signatures': {}, 'network': {}, 'behavior': {}, 'memory': {}, 'strings': {}}
    
    """
    if ("network" in json_file):
        for protocol in ["tcp", 'udp']:
            for i in range(len(json_file["network"][protocol])):
                [json_file["network"][protocol][i].pop(key, "chave: não encontrada") for key in
                 ['offset', 'time', 'dport', 'sport']]
        
        for i in range(len(json_file["network"]["http"])):
            [json_file["network"]["http"][i].pop(key, "chave: não encontrada") for key in
             ['count', 'body', 'version', 'port']]
        
        for i in range(len(json_file["network"]["dns"])):
            [json_file["network"]["dns"][i].pop(key, "chave: não encontrada") for key in ['type', 'answers']]
        
        [json_file["network"].pop(key, "chave: não encontrada") for key in
         ['dns_servers', 'pcap_sha256', 'sorted_pcap_sha256', 'http_ex']]
        
        filtered_json_file["network"] = json_file["network"]
        # aqui no final vou inserir os arquivos que fiz filttro
    
    # tem que mexer aqui pra ficar dentro de uma chave de nome signatures
    if ("signatures" in json_file):
        for i in range(len(json_file['signatures'])):
            filtered_json_file['signatures'][str(i)] = json_file['signatures'][i]['description']
    
    # tem que mexer aqui pra ficar dentro de uma chave de nome signatures
    if ("behavior" in json_file):
        filtered_json_file["behavior"]["summary"] = json_file["behavior"]["summary"] if (
                    "summary" in json_file["behavior"]) else None
        
        filtered_json_file["behavior"]["apistats"] = json_file["behavior"]["apistats"] if (
                    "apistats" in json_file["behavior"]) else None  # Tirei pq acaba sendo um monte de lixo numérico
    """
    
    if "memory" in json_file:
        for i in range(len(json_file["memory"]["modscan"]["data"])):
            for key in ["kernel_module_file", "kernel_module_name"]:
                filtered_json_file["memory"]["modscan_" + str(i) + key] = json_file["memory"]["modscan"]["data"][i][key]
        
        for i in range(len(json_file["memory"]["svcscan"]["data"])):
            for key in ['service_display_name', 'service_binary_path', 'service_name', 'service_type', 'service_state']:
                filtered_json_file["memory"]["svcscan_" + str(i) + key] = json_file["memory"]["svcscan"]["data"][i][key]
        
        for i in range(len(json_file["memory"]["privs"]["data"])):
            for key in ['description', 'filename', 'privilege', 'attributes']:
                filtered_json_file["memory"]["privs_" + str(i) + key] = json_file["memory"]["privs"]["data"][i][key]
        
        for i in range(len(json_file["memory"]["ldrmodules"]["data"])):
            for key in ['init_full_dll_name', 'mem_full_dll_name', 'dll_mapped_path', 'process_name',
                        'load_full_dll_name']:
                filtered_json_file["memory"]["ldrmodules_" + str(i) + key] = \
                json_file["memory"]["ldrmodules"]["data"][i][key]
        
        for i in range(len(json_file["memory"]["devicetree"]["data"])):
            filtered_json_file["memory"]["devicetree_" + str(i) + key] = json_file["memory"]["devicetree"]["data"][i][
                "driver_name"]
        
        for i in range(len(json_file["memory"]["handles"]["data"])):
            for key in ['handle_type', 'handle_name']:
                filtered_json_file["memory"]["handles_" + str(i) + key] = json_file["memory"]["handles"]["data"][i][key]
        
        for i in range(len(json_file["memory"]["dlllist"]["data"])):
            for key in ['process_name', 'commandline']:
                filtered_json_file["memory"]["dlllist_" + str(i) + key] = json_file["memory"]["dlllist"]["data"][i][key]
        
        for i in range(len(json_file["memory"]["callbacks"]["data"])):
            for key in ['type', 'details', 'module']:
                filtered_json_file["memory"]["callbacks_" + str(i) + key] = json_file["memory"]["callbacks"]["data"][i][
                    key]
    
    """
    if ("strings" in json_file):
        filtered_json_file["strings"] = json_file["strings"]
    """
    
    return filtered_json_file


def save_json_file(path: str, filename: str, content):
    with open(path + filename + ".json", "a") as f:
        json.dump(content, f)


def term_count(document: dict) -> dict:
    """
    Recebe o arquivo txt e calcula o TF de cada termo
    """
    tf = {}
    for term in document:
        if str(term).lower() in tf.keys():
            tf[str(term).lower()] += 1
        else:
            tf[str(term).lower()] = 1
    return tf


def order_dict(dictionary: dict) -> dict:
    """
    Recebe como parametro um dicionário e retorna o mesmo dicionário ordenado pelos valores.
    """

    sorted_values = sorted(dictionary.values())  # Sort the values
    sorted_dict = {}
    sorted_keys = sorted(dictionary, key=dictionary.get, reverse=True)  # [1, 3, 2]

    for w in sorted_keys:
        sorted_dict[w] = dictionary[w]
    return sorted_dict

def main():
    path = "..//5 - Cuckoo Reports//"  # Esse caminho é só pra carregar os arquivos JSON
    
    sections = ['signatures', 'network', 'behavior', 'memory', 'strings']
    
    print("Obtendo lista de arquivos na pasta", end='')
    json_file_list = file_list(path)
    print("............completo")
    
    cont = 0
    
    for item in sorted(json_file_list):  # [start_file:finish_file]
        
        file_path = path + item
        
        print("Carregando arquivo nº: " + str(cont) + " Nome: " + item, end="")
        json_file = read_json(file_path)
        print("..............carregado")
        print("Tamanho do arquivo: {:.2f}MB".format(os.path.getsize(file_path) / 1000000))
        
        print("Aplicando filtros ", end='')
        filtered_json_file = filter_dict(json_file)
        json_file = None
        print("........finalizado")
        
        for section in sections:
            
            print("Transformando JSON aninhado em dicionário", end='')
            flat_json = flatten(filtered_json_file[section])
            print("......finalizado")
            
            print("Documento com " + str(len(flat_json)) + " termos")

            print("Extraindo termos do documento", end='')
            terms = list(flat_json.values())
            print("......finalizado")
            
            print("Contagem de termos do documento", end='')
            tf = term_count(terms)
            print("......finalizado")

            print("Ordenando os termos do documento", end='')
            ordered_tf = order_dict(tf)
            print("......finalizado")

            print("Gravando arquivo em disco", end='')
            if not os.path.exists("..//7 - TF-IDF//" + section):
                os.makedirs("..//7 - TF-IDF//" + section)
                
            id = item.split(sep=" ")[0]  # pegar somente o id do nome do arquivo
            save_json_file("..//7 - TF-IDF//" + section + "//", str(id) + ' - ' + section, ordered_tf)
            print(" ...........finalizado")
        
        print(">>>>>Reiniciando<<<<<<")
        
        cont += 1


if __name__ == '__main__':
    main()























