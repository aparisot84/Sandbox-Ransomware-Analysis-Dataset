"""
Tarefas:
    1 - Criar o dicionário de cada arquivo com com as strings e suas quantidades
    2 - Concatenar esse dicionário em um dataframe (usa a função compute TF) - usar o .lower
        pd.DataFrame([wordDictA, wordDictB]) tenho que usar um for para cada arquivo,
        master o dataframe original no wdA e ir revezando no WDB, igual fiz na outra abordagem
    3 - Computar o IDF (usar a função compute IDF)
    4 - Computar o TF-IDF (usar a função compute TF-IDF)
"""

import os
from threading import Thread
import pandas
import pandas as pd


def read_file(filename: str) -> dict:
    """Carrega o arquivo TXT"""
    try:
        with open(filename, "r") as f:
            data = f.readlines()
    except:
        raise Exception(f"Reading {filename} file encountered an error")
    return data


def file_list(path):
    """lista o conteúdo de uma deterinada pasta"""
    
    files = os.listdir(path)
    
    return files


def convert_to_dict(list, filename):
    """
    Converte uma lista de strings recebida como parametro em um dicionário com a quantidade de vezes que cada string aparece nessa lista
    """
    
    dict = {}
    dict["name"] = filename[0:5]
    for item in list:
        item = item.lower()
        if item[0:-1] in dict.keys():
            dict[item[0:-1]] += 1
        elif item not in dict.keys():
            dict[item[0:-1]] = 1
    return dict


def save_dataframe(dataframe):
    """
    Salva o dataframe no formato CSV
    """
    dataframe.to_csv("..//6 - Dataset//TF-IDF.csv", index=False)


def computeTF(wordDict, bow):
    tfDict = {}
    bowCount = len(bow)
    for word, count in wordDict.items():
        tfDict[word] = count / float(bowCount)
    return tfDict


def computeIDF(docList):
    import math
    idfDict = {}
    N = len(docList)
    idfDict = dict.fromkeys(docList[0].keys(), 0)
    for doc in docList:
        for word, val in doc.items():
            if val > 0:
                idfDict[word] += 1
    
    for word, val in idfDict.items():
        idfDict[word] = math.log10(N / float(val))
    return idfDict


def computeTFIDF(tfBow, idfs):
    tfidf = {}
    for word, val in tfBow.items():
        tfidf[word] = val * idfs[word]
    return tfidf


def main():
    path = "..//7 - TF-IDF//"
    
    print("Obtendo lista de arquivos na pasta", end='')
    txt_file_list = file_list(path)
    txt_file_list.sort()  # talvez seja interessante usar
    print("............completo")
    
    df1 = pandas.DataFrame
    
    table = None  # Lista das palavras existentes em todos os documentos, sem repetição
    
    cont = 0
    
    for item in txt_file_list:  # A LIMITAÇÃO DA QUANTIDADE DE ARQUIVOS CARREGADOS PODE SER FEITA AQUI
        
        file_path = path + item  # caminho completo do arquivo
        
        print("Carregando arquivo nº: " + str(cont) + " Nome: " + item, end="")
        txt_file = read_file(file_path)  # Todo: verificar se txt_file é uma lista
        print("..............carregado")
        
        print("Transformando o arquivo de texto em dicionário", end='')
        file_dict = convert_to_dict(txt_file, item)
        print("......finalizado")
        
        if cont == 0:
            print("Transformando o dicionário em dataframe", end='')
            df1 = pd.DataFrame([file_dict])  # retorna o dataframe normalizado
            file_dict = None
            print("......finalizado")
        else:
            print("Transformando o dicionário em dataframe", end='')
            df2 = pd.DataFrame([file_dict])
            file_dict = None
            print("......finalizado")
            print("Concatenando os dataframes", end='')
            table = pandas.concat([df1, df2], ignore_index=True)
            print("......finalizado")
            print("Limpando memória", end='')
            df2 = None
            df1 = table
            table = None
            print("......finalizado")
        
        print(df1.shape)
        
        cont += 1
    print("Gravando dataframe em disco")
    save_dataframe(df1)
    print("......finalizado")


if __name__ == '__main__':
    main()





















