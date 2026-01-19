En esta carpeta se incluyen los dos métodos propuestos para la clasificación de la calidad de audio de Spotify:
uno basado en Machine Learning y otro basado en análisis del tráfico de red.

Método basado en análisis de tráfico (online_quality)

Este método estima la calidad del audio sin usar modelos entrenados, analizando el tráfico de red generado por Spotify en tiempo real.

El proceso es el siguiente:

Detección de IPs de Spotify
Se identifican automáticamente las IPs usadas por Spotify mediante:

Resoluciones DNS de dominios oficiales de Spotify.

Análisis de tráfico HTTPS hacia CDNs habituales (Akamai y Fastly).

Las IPs detectadas se almacenan de forma persistente para reutilizarlas en futuras ejecuciones.

Captura selectiva del tráfico
Una vez identificadas las IPs, se captura únicamente el tráfico asociado a ellas, filtrando el resto del tráfico de red.

Estimación del bitrate
Se consideran solo los paquetes entrantes de mayor tamaño (audio), descartando paquetes de control y metadata.
A partir de los bytes de audio y la duración de la captura se calcula el bitrate efectivo.

Clasificación de la calidad
El bitrate estimado se compara con rangos ajustados al reproductor web de Spotify para clasificar la calidad como:
low, normal, high, high_premium o very_high.

Este enfoque permite estimar la calidad real del streaming de Spotify de forma pasiva, sin acceder al contenido cifrado y sin modificar la aplicación.
