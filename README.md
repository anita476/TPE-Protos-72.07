# Trabajo Práctico Especial - Protocolos de Comunicación (72.07)
## Proxy Socks5v y diseño e implementación de protocolo de monitoreo CalSetting

### Integrantes
* Juan Amancio Oliva Morroni
* Camila Lee
* Matías Leporini
* Ana Negre

### Compilación 
Puede compilarse el trabajo en un entorno Linux con `make` y gcc utilizando el comando make en el directorio root del proyecto. Adicionalmente, pueden limpiarse los binarios con `make clean`.
Se provee, además, una imagen minimalista de Docker para compilar el trabajo y ejecutarlo. La misma puede utilizarse ejecutando los scripts provistos en el directorio “script”: en orden, deben correrse `build.sh`, `run.sh` e `install.sh` (dentro del contenedor). Para ejecutar el proyecto sin Docker, basta con ejecutar `install.sh`.

### Ejecución
La compilación dará por resultado los binarios correspondientes al servidor (`socks5d`) y al programa de administración (`client`) que utiliza el protocolo de monitoreo implementado. Ambos se encontrarán en el directorio `bin`.

#### Servidor (Socks5v y CalSetting)
Para ejecutar el servidor puede utilizar el comando:
`./bin/socks5d`

Los administradores deben ser creados junto al comando para iniciar el servidor mediante `-a user:password`. Opcionalmente, pueden añadirse usuarios con la flag `-u`. 
`./bin/socks5d -a admin:admin -u user1:user1 -u user1:user1`

Además, es posible obtener el detalle de los argumentos aceptados con `-h`.
Se agregaron las flags `-g/ --log <LOG_LEVEL>` para manejar el nivel de logging del servidor. Además, se agregó la flag `-s` (silent) para deshabilitar el logging.

#### Cliente 
Para ejecutar el cliente puede utilizar el comando:
`./bin/client`

Opcionalmente, se puede especificar un host y puerto de la siguiente manera:
`./bin/client -h localhost -p 9090`

Por defecto se intentará ejecutar la UI gráfica de Dialog. Para utilizar la UI de la consola, puede utilizar la flag `--console`.
Además, es posible obtener el detalle de los argumentos aceptados con `--help`.
