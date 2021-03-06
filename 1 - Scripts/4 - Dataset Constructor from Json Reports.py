import json
import os
from threading import Thread
import pandas


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

    #import collections

    obj = {} #collections.OrderedDict()

    def recurse(t, parent_key=""):
        if isinstance(t, list):
            for i in range(len(t)):
                recurse(t[i], parent_key + sep + str(i) if parent_key else str(i))
        elif isinstance(t, dict):
            for k, v in t.items():
                #if v != "NaN": #tentar isso aqui na hora que for rodar
                recurse(v, parent_key + sep + k if parent_key else k)
        else:
            obj[parent_key] = t
    recurse(d)
    return obj


def filter_dict(json_file):

    """
    Filtra o arquivo JSON para concatenar somente as informações escolhidas para compor o dataset. Como os arquivos podem ser muito diferentes, é melhor descartar as entradas indesehjadas ao invés de selecionar as entradas desejadas.
    """

    # A entrada info será parcialmente aproveitada
    [json_file["info"].pop(key, "chave: não encontrada") for key in ['added', 'started', 'duration', 'ended', 'owner', 'category', 'git', 'route', 'custom', 'machine', 'platform', 'version', 'options', "monitor", "package"]]

    #como procmemory é uma lista, pra fazer o pop tem que iterar para fazzer as operações
    # no procmemory vai ficar somente o regions
    json_file.pop("procmemory", "chave: não encontrada")
    #[json_file["procmemory"].pop(key, "chave: não encontrada") for key in ['added', 'started', 'duration', 'ended', 'owner', 'category', 'git', 'route', 'custom', 'machine', 'platform','version', 'options']]

    #vai apagar toda a entrada target
    json_file.pop("target", "chave: não encontrada")

    # A entrada extracted será descartada
    json_file.pop("extracted", "chave: não encontrada")

    # vai apagar toda a entrada virustotal
    json_file.pop("virustotal", "chave: não encontrada")

    # A entrada network pode ser aproveitada, mas talvez de uma maneira que nao seja direta
    json_file.pop("network", "chave: não encontrada")

    # A entrada signatures será descartada
    json_file.pop("signatures", "chave: não encontrada")

    # A entrada static será aproveitada parcialmente (como estou interessando em análise dinamica, static vai ficar na bóia)
    json_file.pop("static", "chave: não encontrada")

    """
    if "static" in json_file:
        [json_file["static"].pop(key, "chave: não encontrada") for key in ['pdb_path', 'peid_signatures', 'signature', 'pe_timestamp', 'imported_dll_count']]
    """

    # A entrada dropped será descartada
    json_file.pop("dropped", "chave: não encontrada")

    # A entrada behavior será aproveitada parcialmente
    #json_file.pop("behavior", "chave: não encontrada")
    json_file['behavior'].pop("generic", "chave: não encontrada")

    """ #tirei o behavior/generic todo
    for i in range(len(json_file["behavior"]["generic"])):
        [json_file["behavior"]["generic"][i].pop(key, "chave: não encontrada") for key in ['pid', 'summary', 'process_path', 'pid']]
        #[json_file["behavior"]["generic"][i]["summary"].pop(key, "chave: não encontrada") for key in ['resolves_host', 'first_seen', 'ppid']]
    """

    for i in range(len(json_file["behavior"]["processes"])):
        [json_file["behavior"]["processes"][i].pop(key, "chave: não encontrada") for key in ['track', 'pid', 'command_line', 'time', 'tid', 'first_seen', 'ppid', 'type', 'process_path', 'process_name']]
        for j in range(len(json_file["behavior"]["processes"][i]['modules'])):
            [json_file["behavior"]["processes"][i]['modules'][j].pop(key, "chave: não encontrada") for key in ['imgsize', 'baseaddr', 'filepath', 'basename']]  #tirei o basename pra testar
        for j in range(len(json_file["behavior"]["processes"][i]['calls'])):
            [json_file["behavior"]["processes"][i]['calls'][j].pop(key, "chave: não encontrada") for key in ['time', 'tid', 'status', 'return_value', 'last_error', 'nt_status', 'buffer', 'arguments', 'category', "api"]]   # coloquei o arguments, o api e o category pra ver o quanto reduz o tamanho do dataframe (testar com a seção que já faz a contagem de chamadas das API)
            #[json_file["behavior"]["processes"][i]['calls'][j]['arguments'].pop(key, "chave: não encontrada") for key in ['stack_pivoted', 'stacktrace', 'module_address', 'process_identifier', 'region_size', 'stack_dep_bypass', 'heap_dep_bypass', 'protection', 'process_handle', 'allocation_type', 'base_address', 'module_handle', 'handle', 'section_handle', 'object_handle', 'file_handle', 'file_path', 'filepath', 'flags', 'create_disposition', 'filepath_r', 'status_info', 'mode', 'file_attributes', 'application_name', 'resource_name', 'basename', 'buffer', 'length', 'offset', 'move_method', 'create_options', 'desired_access', 'shared_access', 'share_access', 'create_disposition', 'section_name', 'commit_size', 'section_handle', 'win32_protect', 'section_offset', 'view_size', 'allocation_type', 'key_handle', 'key_name', 'information_class', 'reg_type', 'id', 'string', 'window_handle', 'text', 'caption', 'language_identifier', 'registers', 'exception', 'value', 'status_code', 'thread', 'thread_handle', 'current_directory', 'track', 'creation_flags', 'inherit_handles', 'function_address', 'ordinal', 'access', 'base_handle', 'regkey_r', 'options', 'processor_count', 'dirpath_r', 'directory_handle', 'file_size', 'free_type', 'thread_identifier', 'parameter', 'stack_size', 'snapshot_handle', 'class_context', 'iid', 'clsid', 'command_line', 'disposition', 'oldifilepath', 'newfilepath', 'newfilepath_r', 'oldfilepath_r', 'hash_handle', 'final', 'oldfilepath', 'machine_name', 'database_name', 'thread_name', 'dirpath', 'computer_name','uuid', 'username', 'size', 'handle_attributes','source_process)identifier', 'source_handle', 'target_process_identifier', 'target_process_handle', 'name_format', 'index', 'open_options','input_buffer', 'device_handle', 'control_code', 'output_buffer', 'handle_attributes', 'source_process_identifier', 'source_handle', 'target_process_identifier', 'target_process_handle', 'target_handle', 'source_process_handle']]
            if len(json_file["behavior"]["processes"][i]['calls'][j]['flags']) == 0:
                json_file["behavior"]["processes"][i]['calls'][j].pop('flags', "chave: não encontrada")
            else:
                [json_file["behavior"]["processes"][i]['calls'][j]['flags'].pop(key, "chave: não encontrada") for key in ['stack_pivoted', 'module_address', 'process_identifier', 'region_size', 'stack_dep_bypass', 'heap_dep_bypass', 'protection', 'process_handle', 'allocation_type', 'base_address', 'module_handle', 'handle', 'section_handle', 'object_handle', 'file_handle', 'file_path', 'filepath', 'flags', 'create_disposition', 'filepath_r', 'status_info', 'mode', 'file_attributes', 'application_name', 'resource_name', 'basename', 'buffer', 'length', 'offset', 'move_method', 'create_options', 'desired_access', 'shared_access', 'share_access', 'create_disposition', 'section_name', 'commit_size', 'section_handle', 'win32_protect', 'section_offset', 'view_size', 'allocation_type', 'key_handle', 'key_name', 'information_class', 'reg_type', 'id', 'string', 'window_handle', 'text', 'caption', 'language_identifier', 'iid', 'clsid', 'creation_flags', 'index', 'open_options', 'control_code', 'cmd', 'folder', 'hook_identifier', 'std_handle', 'modifiers','option', 'algorithm_identifier', 'command_line', 'prcess_name', 'algorythm_identifier']] # process_name algorytm_identifier foram retirados somente para teste

    #if "apistats" in json_file["behavior"]:
    #    for items in json_file["behavior"]["apistats"].keys():
    #        [json_file["behavior"]["apistats"][items].pop(key, "chave: não encontrada") for key in ['__exception__', '_exception_', 'socket', 'closesocket', 'bind', 'PRF', 'setsockopt', 'gethostbyname', 'timeGetTime', 'ioctlsocket' 'select', 'connect', 'timeGetTime', '__anomaly__', 'ioctlsocket', 'select', 'getaddrinfo', 'CreateToolhelp32Snapshot', 'GetNativeSystemInfo', 'CoUninitialize', 'RegCloseKey', 'CoCreateInstanceEx', 'GetSystemInfo', 'RegQueryValueExA', 'MoveFileWithProgressW', 'CryptEncrypt', 'GetSystemWindowsDirectoryW', 'NtQueryValueKey', 'GetFileVersionInfoSizeW', 'NtOpenProcess', 'GetFileAttributesW', 'RegQueryValueExW', 'NtMapViewOfSection', 'Process32NextW', 'GetSystemMetrics', 'GetFileType', 'RegOpenKeyExW', 'SetErrorMode', 'NtAllocateVirtualMemory', 'GetFileInformationByHandle', 'RegOpenKeyExA', 'LdrGetDllHandle', 'NtFreeVirtualMemory', 'CoGetClassObject', 'GetComputerNameW', 'NtReadFile', 'CryptAcquireContextA', 'GetFileSizeEx', 'CreateThread', 'RegCreateKeyExW', 'CoCreateInstance', 'GetSystemDirectoryW', 'SetUnhandledExceptionFilter', 'NtCreateFile', 'GetSystemTimeAsFileTime', 'FindFirstFileExW', 'SetFileAttributesW', 'NtProtectVirtualMemory', 'CoInitializeEx', 'NtCreateSection', 'RegSetValueExW', 'NtOpenKey', 'OpenSCManagerW', 'LdrGetProcedureAddress', 'CoInitializeSecurity', 'SetFilePointerEx', 'NtOpenDirectoryObject', 'Process32FirstW', 'SetEndOfFile', 'LdrLoadDll', 'UuidCreate', 'CreateProcessInternalW', 'NtClose', 'GetUserNameExW', 'LdrUnloadDll', 'DeviceIoControl', 'NtQueryKey', 'NtDuplicateObject', 'IsDebuggerPresent', 'NtOpenFile', 'NtQueryDirectoryFile', 'NtCreateMutant', 'InternetCrackUrlW', 'NtOpenKeyEx', 'NtTerminateProcess', 'NtOpenThread', 'NtQueryInformationFile', 'process_name', 'NtSetInformationFile', 'WSAStartup', 'shutdown', 'NtCreateThreadEx', 'NtDelayExecution', 'NtDeviceIoControlFile', 'WSASocketW', 'NtQuerySystemInformation', 'NtResumeThread', 'GlobalMemoryStatusEx', 'LoadStringW', 'CreateActCtxW', 'SetFilePointer', 'MessageBoxTimeoutW', 'NtOpenSection', 'GetVolumePathNamesForVolumeNameW', 'GetDiskFreeSpaceW', 'FindResourceExW', 'GetAdaptersInfo', 'RegisterHotKey', 'OpenServiceA', 'RemoveDirectoryW', 'NtSetValueKey', 'LookupPrivilegeValueW', 'RegCreateKeyExA', 'NtWriteFile', 'NtEnumerateValueKey', 'GetVolumeNameForVolumeMountPointW', 'SHGetFolderPathW', 'RegSetValueExA', 'GetDiskFreeSpaceExW', 'LookupAccountSidW', 'NtCreateKey', 'SendNotifyMessageW', 'GetShortPathNameW', 'CreateDirectoryW', 'DeleteFileW', 'GetFileInformationByHandleEx', 'DrawTextExW', 'RegEnumKeyW', 'GetKeyState', 'NtUnmapViewOfSection', 'NtQueryAttributesFile', 'GetFileAttributesExW', 'OpenSCManagerA', 'GetVolumePathNameW', 'GetForegroundWindow', 'NtReadVirtualMemory', 'GetCursorPos', 'GetUserNameW', 'LoadResource', 'EnumWindows', 'NetUserGetInfo', 'SearchPathW', 'NtEnumerateKey', 'GetFileSize', 'GetTimeZoneInformation', 'NtOpenMutant', 'SetWindowsHookExW', 'NetShareEnum', 'FindWindowW', 'RegDeleteKeyW', 'SizeofResource', 'UnhookWindowsHookEx', 'OleInitialize', 'NtDeleteKey', 'FindResourceW', 'OpenServiceW', 'RegEnumKeyExW', 'SHGetSpecialFolderLocation', 'WriteConsoleW', 'SetStdHandle', 'NtSetContextThread', 'CryptHashData', 'CryptCreateHash', 'RtlAddVectoredContinueHandler', 'RegQueryInfoKeyW', 'CryptAcquireContextW', 'RegEnumValueW', 'NtGetContextThread', 'NtWriteVirtualMemory', 'ShellExecuteExW', 'RegDeleteValueW', 'GetComputerNameA', 'RegQueryInfoKeyA', 'GetTempPathW', 'WriteConsoleA', 'WriteProcessMemory', 'NtQueueApcThread', 'IWbemServices_ExecQuery', 'FindResourceExA', 'LoadStringA', 'SetWindowsHookExA', 'GetFileVersionInfoW', 'SetFileTime', 'RegEnumKeyExA', 'GetUserNameA', 'Thread32First', 'Thread32Next', 'GetKeyboardState', 'ReadProcessMemory', 'ControlService', 'FindWindowExW', 'GetAdaptersAddresses', 'HttpOpenRequestW', 'InternetConnectW', 'InternetCloseHandle', 'InternetQueryOptionA', 'InternetReadFile', 'HttpSendRequestW', 'InternetOpenW', 'RtlAddVectoredExceptionHandler', 'CryptExportKey', 'NtQueryMultipleValueKey', 'Module32FirstW', 'GetFileVersionInfoSizeExW', 'GetFileVersionInfoExW', 'RemoveDirectoryA', 'GetSystemDirectoryA', 'GlobalMemoryStatus', 'RegDeleteKeyA', 'FindResourceA']]


    for i in range(len(json_file["behavior"]["processtree"])):
        [json_file["behavior"]["processtree"][i].pop(key, "chave: não encontrada") for key in ['track', 'pid', 'first_seen', 'ppid', 'process_name', 'command_line', 'children']]   #coloquei o children pra ver como diminui

    if "summary" in json_file["behavior"]:
        [json_file["behavior"]["summary"].pop(key, "chave: não encontrada") for key in ['file_opened', 'regkey_opened', 'tls_master', 'guid', 'connects_ip', 'regkey_writen', 'command_line', 'regkey_deleted', 'mutex', 'file_read', 'regkey_read', 'file_created', 'file_moved', 'file_written', 'file_recreated', 'directory_created', 'file_failed', 'resolves_host', 'file_deleted', 'directory_removed', 'file_exists', 'directory_enumerated', 'file_opened', 'wmi_query', 'connects_host', 'dll_loaded', 'regkey_written']]    #coloquei dll_loaded e regkey-written para ver como diminui

    # A entrada memory será aproveitada
    json_file.pop("memory", "chave: não encontrada")

    # A entrada debug será descartada
    json_file.pop("debug", "chave: não encontrada")

    # A entrada screenshots será descartada
    json_file.pop("screenshots", "chave: não encontrada")

    # A entrada strings será aproveitada (mas tem que verificar o que pode aproveitar)
    json_file.pop("strings", "chave: não encontrada")

    # A entrada metadata será descartada
    json_file.pop("metadata", "chave: não encontrada")

    # A entrada buffer será descartada
    json_file.pop("buffer", "chave: não encontrada")    #Esta entrada não estava aparecendo inicialmente nas tabelas (pq nao dava pra ver)

    return json_file


def normalize(flat_json):

    """Esta função vai receber o flat json e transformar em dataframe"""

    # preparar para receber chaves diferentes de "apistats" no dicionário (tenho que verificar quais podem entrar)

    keys_list = list(flat_json.keys())
    values_list = list(flat_json.values())

    unique_cols = {}

    for items in keys_list:
        api = items.split(sep='.')[-1]
        if api not in unique_cols:
            unique_cols[api] = 0

    for k, v in flat_json.items():
        k_split = k.split(sep='.')[-1]
        if k_split in unique_cols:
            unique_cols[k_split] = unique_cols[k_split] + v

    # É mais fácil fazer as operações num dicionário mononivel e depois transformar em um dataframe

    df1 = pandas.json_normalize(unique_cols)

    return df1

def main():

    path = "//media//ubuntu//a38624f9-5396-4f62-93b6-3e791cb1b38d/Análises/cuckoo pack/Códigos/Cuckoo Report Bank//JSON//"

    print("Obtendo lista de arquivos na pasta", end='')
    json_file_list = file_list(path)
    #json_file_list.sort()  #talvez seja interessante usar
    print("............completo")

    df1 = pandas.DataFrame

    cont = 0

    for item in json_file_list:     # [start_file:finish_file]

        file_path = path + item

        print("Carregando arquivo nº: " + str(cont) + " Nome: " + item, end="")
        json_file = read_json(file_path)    #aqui que tem que entrar o tratamento do json
        print("..............carregado")

        print("Aplicando filtros ", end='')
        filtered_json_file = filter_dict(json_file)
        json_file = None
        print("........finalizado")

        print("Transformando JSON aninhado em dicionário", end='')
        flat_json = flatten(filtered_json_file)
        filtered_json_file = None
        print("......finalizado")

        print("Tamanho do arquivo: {:.2f}MB".format(os.path.getsize(file_path)/1000000))
        print("Dicionário com " + str(len(flat_json)) + " linhas")

        ###############################################################################

        #print(type(flat_json))     #agora flat_json é um dict

        #df1 = normalize(flat_json) #retorna o dataframe normalizado

        # TODO: A conversão das colunas do DF1 deve ser feita aqui, pois preciso dele normalizado. Vou tentar normalizar manualmente e depois coocar no dataframe, se der certo, nao vou precisar usar a função filtro.

        ###############################################################################

        if cont == 0:

            print("Normalizando arquivo", end="")
            #df1 = pandas.json_normalize(flat_json)
            df1 = normalize(flat_json)  # retorna o dataframe normalizado
            flat_json = None
            print(" ...........finalizado")
            #TODO: A conversão das colunas do DF1 deve ser feita aqui, pois preciso dele normalizado. Vou tentar normalizar manualmente e depois coocar no dataframe, se der certo, nao vou precisar usar a função filtro.

        else:

            print("Normalizando arquivo", end="")
            df2 = normalize(flat_json)  # retorna o dataframe normalizado
            #df2 = pandas.json_normalize(flat_json)
            flat_json = None
            print(" ...........finalizado")

            #TODO: A conversão das colunas do DF1 deve ser feita aqui, pois preciso dele normalizado. Vou tentar normalizar manualmente e depois coocar no dataframe, se der certo, nao vou precisar usar a função filtro.

            print("Concatenando arquivo", end="")
            table = pandas.concat([df1, df2], ignore_index=True)
            print(" ...........finalizado")

            print("Copiando Dataframe", end="")
            df1 = table
            print(" ...........copiado")

            print("Limpando dataframes desnecessários", end="")
            table = None
            df2 = None
            print(" ...........finalizado")

            print("Tabela final: ", df1.shape)

            print(">>>>>Reiniciando<<<<<<")

        if (cont != 0) and (int(cont % 5)) == 0:

            # O arquivo CSV é MENOR que o arquivo PKL, porém o pkl é binário, o que faz com que a leitura e gravação sejam beeeeem mais rápidas

            print("Gravando arquivo em disco")
            to_pickle_args = str(cont) + ".pkl"
            #to_csv_args = str(cont) + ".csv"
            write_thread = Thread(target=df1.to_pickle, args=[to_pickle_args])
            #write_thread = Thread(target=df1.to_csv, args=[to_csv_args])
            write_thread.start()
            print("Arquivo gravado em disco")

            if cont >= 10:

                remove_file_args = (str(cont-5)) + ".pkl"
                #remove_file_args = (str(cont - 5)) + ".csv"
                remove_thread = Thread(target=os.remove, args=[remove_file_args])
                remove_thread.start()

        elif item == json_file_list[-1]:

            remove_file_args = (str(int(cont % 5)) * 5) + ".pkl"
            #remove_file_args = (str(int(cont % 5)) * 5) + ".csv"
            remove_thread = Thread(target=os.remove, args=[remove_file_args])
            remove_thread.start()

        cont+=1


if __name__ == '__main__':
    main()


