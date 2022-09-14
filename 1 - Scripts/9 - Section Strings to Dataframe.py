import collections
import json
import os
import math
import pandas
from pandas import DataFrame
import time

"""
    1 - Carrega os arquivos de uma determinada pasta ('network', 'signatures', 'behavior', 'memory', 'strings')
    2 - Cria a lista geral de termos para cada arquivo referente a uma determinada seção
    2.5 - Pega os x% de termos que mais aparecem em cada seção e junta para calcular o TF e o IDF (não implementado)
    3 - Calcula o TF de cada termo
    4 - Calcula o IDF de cada termo
    5 - Calcula o TF-IDF
    6 - Concatena os resuktados em um dataframe
    7 - Salva a tabela na pasta superior
    8 - Faz a mesma coisa para os arquivos das outras pastas outros arquivos
    
    OBS: Antes de tentar cortar os termos por quantidade de vezes que aparece, vou tentar cada seção usando tudão
"""

# https://stackoverflow.com/questions/71213250/how-to-get-tf-idf-value-of-a-word-from-all-set-of-documents

# O nome disso def json_file_list(path: str, sections: list) -> dict: (tipo de parametro e retorno da função) se chama annotations. Usei pra me auxiliar a construir as funções, pois caso a chamada esteja fora deste padrão, a própria IDE já avisa que está esperandi um tipo e recebendo outro (comentário para o Github)

# Houve também uma tentativa de colorizar a saída no terminal e acabei esbarrando nas funções de logging do python e em um outro jeito usando sobrecarga na função print (Isso foi anotado no OneNote)

# As funções que mais demoram são a de transformação em um dataframe e a de fillna

# Depois de muito tentar resolver problemas, descobri que é o excel que abre o arquivo CSV com os caracteres errados, o que no final das contas não importa, pois é o pandas que tem que abrir o arquivo corretamente

def json_file_list(path: str, sections: list) -> dict:
    """
    Lista o conteúdo de uma determinada pasta e retorna um dicionário com o conteúdo referente a cada pasta de cada seção.
    """
    file_list_dict = dict.fromkeys(sections)
    for section in sections:
        file_list_dict[section] = os.listdir(path + section)
    return file_list_dict


def read_json(filename: str) -> dict:
    """
    Carrega o arquivo JSON.
    """
    try:
        with open(filename, "r") as f:
            data = json.loads(f.read())
    except:
        raise Exception(f"Reading {filename}: file encountered an error")
    return data


def read_file(path: str, section: str) -> list:
    """
    Carrega o arquivo TXT.
    """
    if section in path:
        try:
            with open(path, "r") as f:
                data = f.readlines()
        except:
            raise Exception(f"Reading {path} file encountered an error")
        return data


def save_dataframe(dataframe: DataFrame, path: str, section: str):
    """
    Salva o dataframe no formato CSV.
    """
    dataframe.to_csv(path + section + ".csv", index=False)


def flatten(d: dict, sep=".") -> collections.OrderedDict:
    """
    Transforma o json aninhado num dicionário com os nós da árvore concatenados em um único nível, com ponto como separador das chaves do dicionário original
    """
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


def normalize(flat_json):
    """
    Função que transforma o flat json em dataframe.
    """
    keys_list = list(flat_json.keys())
    unique_cols = {}
    for items in keys_list:
        api = items.split(sep='.')[-1]
        if api not in unique_cols:
            unique_cols[api] = 0
    for k, v in flat_json.items():
        k_split = k.split(sep='.')[-1]
        if k_split in unique_cols:
            unique_cols[k_split] = unique_cols[k_split] + v
    df1 = pandas.json_normalize(unique_cols)
    return df1


def compute_tf(word_dict):
    """
    Calcula a frequência de termos de um documento. A frequência de termos é a quantidade de vezes que aquele termo aparece sobre a quantidade de termos que tem naquele documento.
    """
    tf_dict = {}
    word_count = len(word_dict.keys())
    for word, count in word_dict.items():
        tf_dict[word] = count / float(word_count)
    return tf_dict


def compute_idf(corpus: dict, wordlist: list) -> dict:
    """
    Calcula o inverso da quantidade de documentos em que determinado termo aparece, utilizando a fórmula IDF(t) = log_e(Total number of documents / Number of documents with term t in it).
    """
    idf_dict = dict.fromkeys(wordlist, 0.0)
    N = len(corpus.keys())
    for documents in corpus:
        for word, value in corpus[documents].items():
            if value > 0:
                idf_dict[word] += 1
    for word, value in idf_dict.items():
        idf_dict[word] = math.log10(((1 + N) / (1 + value)) + 1)
    return idf_dict


def compute_tfidf(tf: dict, idf: dict) -> dict:
    """
    Calcula o TF-IDF do corpus (TF*IDF de cada termo).
    """
    tf_idf = {}
    for document_id in tf:
        tf_idf[document_id] = {}
        for term, value in tf[document_id].items():
            tf_idf[document_id][term] = value * idf[term]
    return tf_idf


def create_wordlist(corpus: dict) -> list:
    """
    Cria a lista de termos a partir do corpus de documentos (dicionário).
    """
    wordlist = []
    
    """
    # Este trecho, apesar de ter a lógica bastante óbvia, não estava sendo eficiente para a geração da wordlist.
    for documents in corpus:
        for term in corpus[documents].keys():
            if term not in wordlist:
                wordlist.append(term)
    """
    # Confecciona a wordlist de maneira mais eficiente que iterar cada termo em cada documento e comparar um a um com toda a wordlist.
    temp_list = []
    for documents in corpus:
        for term in corpus[documents].keys():
            temp_list.append(term)
    wordlist = list(dict.fromkeys(temp_list))
    return wordlist


def convert_to_dataframe(tf_idf: dict):
    """
    Converte o dicionário com o tf_idf em um dataframe.
    """
    df1 = pandas.DataFrame
    cont = 0
    sample_id = sorted(list(tf_idf.keys()))
    for report in sample_id:
        if cont == 0:
            print(cont, "- Preparando o dicionário da amostra", report, "para transformar em Dataframe", end='')
            flatted = flatten(tf_idf[report])
            df1 = normalize(flatted)
            flatted = None
            print("......finalizado")
        else:
            print(cont, "- Preparando o dicionário da amostra", report, "para transformar em Dataframe", end='')
            flatted = flatten(tf_idf[report])
            df2 = normalize(flatted)
            flatted = None
            print("......finalizado")

            print("Concatenando Dataframes", end='')
            table = pandas.concat([df1, df2], ignore_index=True, axis=0)
            df1 = table
            print("......finalizado")
            
            print("Limpando memória", end='')
            table = None
            df2 = None
            print("......finalizado")
            
            #imprimir o tamanho do dataframe
        cont += 1
    df1["id"] = sample_id
    return df1


def df_process(table: DataFrame) -> DataFrame:
    """
    FSubstitui os valores N/A por zero no dataframe.
    """
    for column in table.columns:
        table[column].fillna(0, inplace=True)
    return table


def strip_chars(dictionary: dict) -> dict:
    """
    Refaz as strings que são as chaves do dicionário sem os pontos para não interferir na função flatten.
    """
    
    stripped_dict = {}
    char_to_replace = {'.', ',', ' ', '\n', '\r'}    # ponto virgula e espaço por nada
    for char in char_to_replace:
        stripped_dict = {k.replace(char, ''): v for k, v in dictionary.items()}
    
    # Substituição simples do ponto por nada nas strings
    # stripped_dict = {k.replace('.', ''): v for k, v in dictionary.items()}
    
    # tentativa de substituir as strings por hashes
    # stripped_dict = {}
    # for key, value in dictionary.items():
    #    stripped_dict[hash(key)] = value
    
    return stripped_dict

######################################################
######################################################


def main():
    
    # Por algum motivo iterar a lista das seções estava dando erro. Me parece que as chaves estavam se misturando, mas rodar o sccript pra cada chave parece resolver o problema
    
    # Para a seção network, commo tem muito ponto nas strings (IP, por exemplo), a função flatten está bagunçando a arrumação do dataframe
    
    #sections = ['behavior',  'memory', 'network', 'signatures', 'strings']

    # sections = ['behavior']             # Aparente problema de formatação (erro no carregamento)
    # sections = ['memory']             # tabela ok
    sections = ['network']            # Aparente problema de formatação (o CSV fica bagunçado)
    # sections = ['signatures']         # tabela ok
    # sections = ['strings']            # tabela ok

    path = "..//7 - TF-IDF//"
    
    tf, idf, tf_idf = {}, {}, {}
    
    print("Obtendo lista de arquivos na pasta de seção", end='')
    file_list_dict = json_file_list(path, sections)  # cria o dicionário com todos os arquivos de todas as seções
    print("............completo")
    
    for section in sections:
        
        wordlist = []
        
        section_corpus = {}
        
        for file in file_list_dict[section]:
            document_id = int(file[0:4])  # Serve para manter o ID de cada relatório
            
            file_path = path + section + "//" + file  # Caminho dos arquivos dentro de cada seção
            
            print("Carregando arquivo", file, end="")
            document_json = read_json(file_path)
            stripped_document = strip_chars(document_json)   # Esta função foi somente para teste da seção network
            print("..............concluído")

            print("Calculando frequencia de termos (TF)", end="")
            tf[document_id] = compute_tf(stripped_document)
            #tf[document_id] = compute_tf(document_json)
            print("..............concluído")
            

            print("Criando o section_corpus com os documentos", end="")
            section_corpus[document_id] = stripped_document
            #section_corpus[document_id] = document_json
            print("..............concluído")

        print("Criando wordlist", end="")
        wordlist = create_wordlist(section_corpus)
        print("..............concluído")
        print("Wordlist com " + str(len(wordlist)) + " termos")
        
        print("Calculando a frequência inversa dos termos nos documentos (IDF)", end="")
        idf = compute_idf(section_corpus, wordlist)
        print("..............concluído")

        print("Calculando TF-IDF", end="")
        tf_idf = compute_tfidf(tf, idf)
        print("..............concluído")
        
        print("Transformando a tabela", section, "em dataframe")
        dataframe_tf_idf = convert_to_dataframe(tf_idf)
        
        print("Ajustando o dataframe", end="")
        processed_dataframe_tf_idf = df_process(dataframe_tf_idf)
        print("..............concluído")
        
        print("Gravando arquivo do dataframe em disco", end="")
        save_dataframe(processed_dataframe_tf_idf, path, section)
        print("..............concluído\n")
        
        #TODO: em algum ponto, inserir a lógica de seleção de x% das strings de cada arquivo para compor os calculos para o dataframe (fazer isso depois de testar os arquivos dos conjuntos)
        
        #TODO: testar se é possível juntar todas as seções e aplicar o tf-idf de uma única vez (é possivel, mas vei demorar muito, por causa da quantidade de strings em cada seção) - Talves não seja não
    
if __name__ == '__main__':
    main()


