# Obligatorio 2 – Redes de Computadoras

Este repositorio contiene el trabajo que hicimos para el segundo obligatorio de Redes de Computadoras. El enfoque fue analizar y corregir el comportamiento del router en distintos escenarios de reenvío y enrutamiento, tanto en la parte de forwarding como en el manejo del protocolo PWOSPF.

## Lo que aprendí

- A usar Wireshark para analizar tráfico de red (.pcap) y entender qué estaba fallando y por qué.
- A configurar topologías con varios hosts, interfaces y enlaces, identificando qué debía pasar en cada caso.
- A encontrar errores en el código del router (en C), modificarlo y ver cómo eso impactaba en la red.
- A entender mejor cómo funciona un protocolo de enrutamiento como OSPF simplificado (PWOSPF), viendo cómo los routers intercambian información de estado.
- A trabajar con conceptos clave como máscaras de subred, tablas de forwarding, TTL, ARP, y manejo de ICMP.

## Estructura

- `CapturasOb2/` – Capuras .pcap antes y después de corregir los errores.
- `reenvio/` – Código relacionado al reenvío básico de paquetes.
- `enrutamiento/` – Código que se modificó para manejar el protocolo PWOSPF.
- `Obligatorio2Grupo03.pdf` – Informe con el análisis completo de cada parte del obligatorio.

