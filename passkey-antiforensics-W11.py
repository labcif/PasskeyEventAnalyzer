from Evtx.Evtx import Evtx
import winreg

def apagar_entrada(caminho_completo):
    try:
        # Separa o caminho completo para obter a chave pai e o subcaminho
        chave_pai, subcaminho = caminho_completo.split("\\", 1)
        
        # Obter o handle da chave pai
        if chave_pai == "HKEY_USERS":
            chave_pai_handle = winreg.HKEY_USERS
        else:
            raise ValueError("Chave pai não suportada. Suporte apenas para HKEY_USERS neste exemplo.")
        
        # Apaga a chave especificada
        winreg.DeleteKey(chave_pai_handle, subcaminho)
        print(f'A chave "{caminho_completo}" foi apagada com sucesso.')
        
    except FileNotFoundError:
        print(f'A chave "{caminho_completo}" não foi encontrada.')
    except PermissionError:
        print('Permissão negada. Tente executar o script como administrador.')
    except Exception as e:
        print(f'Ocorreu um erro: {e}')

# Exemplo de uso:
caminho_completo = r'HKEY_USERS\S-1-5-20\Software\Microsoft\Cryptography\FIDO\S-1-5-21-3469369403-1375254044-481706203-1001\LinkedDevices\a33eabab5d51f6eda0b06883d0de5d41'

apagar_entrada(caminho_completo)
