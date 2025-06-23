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

Opción	Significado

-p-	Escanea todos los puertos (1-65535), no solo los más comunes.
-sC	Usa los scripts por defecto de Nmap (default scripts) para detección.
-sV	Intenta detectar la versión del servicio que corre en cada puerto.
-n	No resuelve DNS, es más rápido. No intenta convertir IPs en nombres.
172.17.0.2	Es la IP objetivo del escaneo (puede ser una máquina local o de red).

