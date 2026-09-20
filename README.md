# skyport-vulnerable-demo

## ¿Qué es esto?

Skyport es un pequeño sistema ficticio para gestionar vuelos y pasajeros, creado para el laboratorio de auditoría de sistemas. No es una aplicación real ni está diseñada para producción. Su objetivo es servir como práctica, ya que cada función contiene intencionalmente un error de seguridad diferente. De esta manera, se puede practicar cómo una herramienta SAST detecta estos problemas y cómo corregirlos.

La idea es crear una aplicación donde los pasajeros puedan iniciar sesión, consultar el clima de su aeropuerto de origen y descargar su tiquete de embarque. Sin embargo, para este laboratorio se incluyeron diferentes errores de seguridad de forma intencional, similares a los que pueden aparecer en proyectos reales cuando se prioriza la rapidez de desarrollo sobre la seguridad.

## Las fallas que se cortaron

El inicio de sesión tiene varios problemas de seguridad. Primero, las contraseñas se guardan usando MD5, un algoritmo antiguo y poco seguro para proteger contraseñas. Además, la consulta que verifica el usuario y la contraseña se construye directamente con los datos ingresados, sin usar consultas parametrizadas. Esto permite que un atacante pueda intentar manipular el campo de inicio de sesión para evadir la autenticación.

El endpoint del clima también tiene un problema. La aplicación toma el código del aeropuerto ingresado por el usuario y lo utiliza directamente en un comando de terminal. Si se introduce un valor malicioso, podría hacer que la aplicación ejecute comandos que no estaban previstos.

La descarga de tiquetes tampoco valida correctamente el nombre del archivo solicitado. Esto permite intentar acceder a archivos que están fuera de la carpeta destinada a los tiquetes.

Además, una clave de API está escrita directamente en el código fuente. Esto significa que cualquier persona con acceso al código podría obtenerla. Lo correcto sería guardarla en una variable de entorno o en un gestor de secretos.

Por último, algunas dependencias del proyecto están desactualizadas. Se utilizan versiones de Flask y PyYAML que tienen vulnerabilidades conocidas y que ya cuentan con versiones más recientes para corregirlas.

## Resumen técnico

| # | Falla | CWE | Dónde vive | Endpoint |
|---|-------|-----|------------|----------|
| 1 | Secreto embebido en el código | CWE-798 | **SkyWay.py** (constante WEATHER_API_KEY) | - |
| 2 | Inyección SQL | CWE-89 | **SkyWay.py**, función login | POST /login |
| 3 | Hashing débil (MD5) | CWE-916 | **SkyWay.py**, funciones login y register | /login, /register |
| 4 | Inyección de comandos | CWE-78 | **SkyWay.py**, función flight_weather | GET /flights/weather |
| 5 | Path Traversal | CWE-22 | **SkyWay.py**, función get_boarding_pass | GET /boarding-pass/<filename> |
| 6 | Dependencia desactualizada | CWE-1104 | requirements.txt | Flask 0.12.2, PyYAML 5.1 |

## Cómo correrlo (opcional)

```bash
pip install -r requirements.txt
python3 SkyWay.py
```
**Fuentes**

https://cwe.mitre.org/