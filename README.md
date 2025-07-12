# Trabajo Práctico Especial - Protocolos de Comunicación (72.07)
## Proxy Socks5v y diseño e implementación de protocolo de monitoreo CalSetting

### Integrantes
* Juan Amancio Oliva Morroni
* Camila Lee
* Matías Leporini
* Ana Negre

### Compilación 
Puede compilarse el trabajo en un entorno Linux con make y gcc utilizando el comando `make`. 
> Puede limpiarse el output con `make clean` 

> Se provee, además, una imagen minimalista de Docker para compilar el trabajo y ejecutarlo.
>
> La misma puede utilizarse mediante los scripts provistos (`build.sh`, `run.sh` e `install.sh`)

### Ejecución
La compilación dará por resultado los binarios correspondientes al servidor (`socks5d`) y al programa de management (`client`) que utiliza el protocolo de monitoreo implementado.

#### Servidor (Socks5v y CalSetting)
Para inicializar el servidor puede utilizar el comando:

` ./bin/socks5d [ARGS] `

Para obtener el detalle de los argumentos aceptados puede utilizar la flag `-h`

#### Cliente 
Para ejecutar el cliente puede utilizar el comando:

`./bin/client`

Para obtener el detalle de los argumentos aceptados puede utilizar la flag `--help`.

Por defecto se intentará ejecutar la UI de Dialog, en caso de utilizar la UI de consola puede utilizar la flag `--console`.
> **Aclaración**
>
> Se agregaron las flags -g/ --log <LOG_LEVEL> para manejar el nivel de logging del servidor.
> Además, se agrego la flag -s (silent) para deshabilitar el logging
