# PyBackuper


## Tutorial:

#### 1. Leia o arquivo licença e só proceda caso concorde.

#### 2. Crie uma chave de API "segredo de cliente":
Essa é usada para identificar sua cópia do aplicativo no sistema OAuth do Google para que eles possam conceder a você acesso às chamadas de API do Google Drive.

 O motivo é simples: o Google tornou muito difícil e complicado compartilhar chaves de aplicativo API, mesmo para software gratuito. Posso não ter tempo e eu não quero ser responsável por gerenciar as credenciais deste aplicativo com o Google.

 Em vez disso, você está criando suas próprias credenciais de aplicativo, deixando você mesmo é responsável por compartilhar ou não, essas credenciais. (Recomendo não compartilhar)
1. Siga os dois tutoriais em: https://developers.google.com/workspace/guides/create-project
 - Na parte "Enable a Google Workspace API", etapa 5, em vez de "Gmail API" escolha "Drive API".
2. Agora siga este https://developers.google.com/workspace/guides/create-credentials
 - No passo 6, se a opção interno não estiver disponível, você pode usar externo.
(Não será realmente externo sem você enviar o aplicativo
para aprovação, e não é necessário enviar, não se preocupe.)
 - Na etapa 10, você só precisa adicionar um escopo: "https://www.googleapis.com/auth/drive" (isso permite apenas a modificação de arquivos criados usando o
aplicativo, qualquer outro arquivo no seu drive não pode ser alterado.)
3. Agora siga a parte "Create a OAuth client ID credential".
 - Na etapa 5, escolha "Create Desktop application credentials".
##### Salve o arquivo .json em algum lugar acessível para nosso aplicativo.

#### 3. Crie a pasta do seu projeto, copie o arquivo "config_example.py" (você pode renomeá-lo).
 Altere essas linhas:
- self.local_folder_path: caminho para a pasta que você deseja fazer backup.
 - self.remote_folder_path: caminho remoto para a pasta no Google Drive para salvar o backup.
 - self.gdrive_secret_file_path: local onde você salvou o arquivo .json da etapa anterior (1.).

4. Crie um script simples para executar nosso aplicativo:
   (Modifique alguns campos)
```python
#!/usr/bin/python3
    import sys

    sys.path.insert (1, "caminho/para/nosso/aplicativo/backuper") # ou instale na pasta site-packages
    importar backuper.app como aplicativo
    import backuper.gdriveremotestorage como gdriveremotestorage

    if __name__ == "__main__":
            app = app.App(config_file_path = "caminho/para/config.py")
            app.setup(gdriveremotestorage.GDriveRemoteStorage)
            app.push() # push, pull, sync or clear
```
#### Notas:
 - **push**: enviar arquivos locais para a pasta remota, limpar arquivos remotos que não estejam no local.
 - **pull**: recebe arquivos remotos na pasta local, limpa os arquivos locais não remotos.
 - **clear**: apaga tudo em sua pasta remota (apenas o definido no config.py).
 - **sync**: realiza um pull ou push dependendo do estado local / remoto dos arquivos.

Cuidado, para usar a sincronização você precisa seguir estas etapas:
- Comece sua pasta com um pull ou push.
- Lembre-se de atualizar com pull / push / sync toda vez que terminar seu "trabalho",
   caso contrário, o aplicativo não lidará com o conflito e da próxima vez que você usar a sincronização,
   se você atualizou o drive remoto com outro trabalho (mais recente, talvez?), a sincronização irá
   decidar que o estado "alterado" significa "novo" e substituirá seu trabalho remoto.
   Para evitar isso, você pode usar antes pull ou push para consertar.