#!/bin/bash

# Script simplificado para debug
#set -x  # Debug mode

# Configuración
SOCKS_HOST="127.0.0.1"
SOCKS_PORT="1080"
MANAGEMENT_PORT="8080"
SERVER_BINARY="./bin/socks5d"

# Función para verificar si puerto está en uso
check_port() {
    if command -v nc >/dev/null 2>&1; then
        nc -z "$1" "$2" 2>/dev/null
    else
        timeout 1 bash -c "</dev/tcp/$1/$2" 2>/dev/null
    fi
}

# Matar procesos previos
echo "Limpiando procesos previos..."
pkill -f "$SERVER_BINARY" 2>/dev/null || true
sleep 2

# Verificar que el puerto esté libre
if check_port "$SOCKS_HOST" "$SOCKS_PORT"; then
    echo "Puerto $SOCKS_PORT ya está en uso"
    exit 1
fi

echo "Iniciando servidor..."
echo "Comando: $SERVER_BINARY -p $SOCKS_PORT -P $MANAGEMENT_PORT -u admin:admin:admin"

# Iniciar servidor en background con logs
$SERVER_BINARY -p "$SOCKS_PORT" -P "$MANAGEMENT_PORT" -u admin:admin:admin > server_output.log 2>&1 &
SERVER_PID=$!

echo "PID del servidor: $SERVER_PID"

# Esperar que el servidor inicie
echo "Esperando que el servidor inicie..."
for i in {1..15}; do
    if check_port "$SOCKS_HOST" "$SOCKS_PORT"; then
        echo "Servidor iniciado correctamente en puerto $SOCKS_PORT"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "El servidor murió durante el inicio"
        echo "Logs del servidor:"
        cat server_output.log
        exit 1
    fi
    echo "Intento $i/15..."
    sleep 1
done

if ! check_port "$SOCKS_HOST" "$SOCKS_PORT"; then
    echo "Servidor no responde después de 15 segundos"
    echo "Logs del servidor:"
    cat server_output.log
    kill "$SERVER_PID" 2>/dev/null
    exit 1
fi

# Test simple con netcat si está disponible
if command -v nc >/dev/null 2>&1; then
    echo "Test básico con netcat..."
    
    # Test 1: Conexión simple
    echo "Test 1: Conexión básica"
    if timeout 5 nc -z "$SOCKS_HOST" "$SOCKS_PORT"; then
        echo "Conexión TCP exitosa"
    else
        echo "No se puede conectar por TCP"
    fi
    
    # Test 2: SOCKS5 Hello
    echo "Test 2: SOCKS5 Hello"
    response=$(printf '\x05\x01\x00' | timeout 5 nc "$SOCKS_HOST" "$SOCKS_PORT" | od -t x1 -A n)
    if [[ "$response" == *"05 00"* ]]; then
        echo "SOCKS5 Hello exitoso"
    else
        echo "SOCKS5 Hello falló. Respuesta: $response"
    fi
else
    echo "  netcat no disponible, saltando tests básicos"
fi

# Test con curl si está disponible
if command -v curl >/dev/null 2>&1; then
    echo "Test con curl..."
    
    # Test a través del proxy SOCKS5
    if timeout 10 curl -x socks5://"$SOCKS_HOST":"$SOCKS_PORT" http://httpbin.org/ip 2>/dev/null; then
        echo "Test con curl exitoso"
    else
        echo "Test con curl falló"
    fi
else
    echo "curl no disponible"
fi

# Cleanup
echo "Limpiando..."
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null

echo "Tests completados"