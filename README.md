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

ffuf	Es la herramienta de fuzzing rápida para URL y archivos (como dirb o gobuster, pero más moderna y rápida).

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






