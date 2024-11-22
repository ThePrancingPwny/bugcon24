# Laboratorio 1.1 - Creación de detecciones

## Descripción

Ya has aprendido como se hace uso de una metodologia de ingenieria de detección, ahora puedes aplicar este conocimiento y generar pseudo código que puede convertirse en consultas en un SIEM.

___

## Objetivos

* Convertir las fuentes de datos presentes en la base de conocimiento del Mitre ATT&CK en posibles consultas que pueden ser usadas para identificar el uso de la técnica de Windows Services

___

## Requirimientos

* Web Browser
* Editor de texto

___


#### *Actividad*
 
       
        1. Identifica los Data Sources y Data Components que no fueron incluidos en el ejemplo y crea un Modelo de Datos a partir de la información proporcionada por el sitio Mitre ATT&CK ID:T1543.003 

        2. Mapea las fuentes de datos a sensores que pueden estar presentes en un equipo Windows (Sysmon, Windows Security Logs o EDR) 

        3. Escribe las posibles detecciones que te ayuden a identificar la ejecución de esta técnica


> **Valuable Tip:**
> *Has uso de la nueva actualización del Mitre ATT&CK, esta nueva versión incluye más de 230 nuevos analiticos, adicionalmente puedes consultar los repositorios de detecciones de proveedores de SIEM (Elastic, Splunk) así como aquellos mantenidos por la comunidad (Sigma Rules)*