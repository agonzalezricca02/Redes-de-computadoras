/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "pwospf_protocol.h"
#include "sr_pwospf.h"

uint8_t sr_multicast_mac[ETHER_ADDR_LEN];

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa el subsistema OSPF */
    pwospf_init(sr);

    /* Dirección MAC de multicast OSPF */
    sr_multicast_mac[0] = 0x01;
    sr_multicast_mac[1] = 0x00;
    sr_multicast_mac[2] = 0x5e;
    sr_multicast_mac[3] = 0x00;
    sr_multicast_mac[4] = 0x00;
    sr_multicast_mac[5] = 0x05;

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */






















struct sr_rt *buscar_en_tabla_enrutamiento(struct sr_instance *sr, uint32_t ip_dest){
  struct sr_rt *enrut = sr->routing_table;
  struct sr_rt *it = enrut;
  struct sr_rt *best_match = NULL;
  int max_prefix_len = -1;

  while(it != NULL){
    uint32_t prefijo = it->dest.s_addr & it->mask.s_addr;
    uint32_t dest_prefijo = ip_dest & it->mask.s_addr;
    if(prefijo == dest_prefijo){
      int longitud_del_prefijo_actual = __builtin_popcount(it->mask.s_addr); /*Cuenta los bits en la máscara*/
      if(longitud_del_prefijo_actual > max_prefix_len){
        max_prefix_len = longitud_del_prefijo_actual;
        best_match = it;
      }
    }
    it = it->next;
  }
  return best_match;
}







/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
  /*
  * Reservar memoria para el paquete
  */
  if(type == 3 && code == 1){
    struct sr_if *iface_chequeo = sr_get_interface_given_ip(sr,ipDst);
    if(iface_chequeo != NULL){
      printf("Solicitud ARP al mismo router, quedaria en loop infinito");
      return;
    }
  }
  size_t icmp_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *icmp_packet = malloc(icmp_size);
  if (icmp_packet == NULL) {
      fprintf(stderr, "Error al asignar memoria para el paquete ICMP.\n");
      return;
  }
  memset(icmp_packet, 0, icmp_size); /* Limpiar el paquete */

  /*
  * Construir el cabezal ICMP
  */
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0; /* No utilizado */
  icmp_hdr->next_mtu = 0; /* No utilizado para port unreachable, net unreachable ni time exceeded*/

  memcpy(icmp_hdr->data, ipPacket, sizeof(sr_ip_hdr_t)); /* Copiar el encabezado IP que causó el error */
  memcpy(icmp_hdr->data + sizeof(sr_ip_hdr_t), ipPacket + sizeof(sr_ip_hdr_t), 8); /* Copiar los primeros 8 bytes del payload del paquete icmp original */

  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /*
  * Construir el cabezal IP
  */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *bestMatch = buscar_en_tabla_enrutamiento(sr, ipDst);
  if (bestMatch == NULL) {
    printf("No se encontró una ruta para el paquete ICMP de error");
    free(icmp_packet);    
    return;
  }
  struct sr_if *iface_salida = sr_get_interface(sr, bestMatch->interface);
  if (iface_salida == NULL) {
    printf("No se encontró la interfaz de salida para el paquete ICMP de error");
    free(icmp_packet);
    return;
  }
  ip_hdr->ip_src = iface_salida->ip;
  ip_hdr->ip_dst = ipDst;

  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;

  ip_hdr->ip_sum = 0;                 
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /*
  * Construir el paquete Ethernet
  */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *)icmp_packet;

  eHdr->ether_type = htons(ethertype_ip);
  memcpy(eHdr->ether_shost, iface_salida->addr, ETHER_ADDR_LEN); /*Seteo la dirección MAC de origen*/

  uint32_t arp_target_ip = (bestMatch->gw.s_addr == 0) ? ipDst : bestMatch->gw.s_addr;
  struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), arp_target_ip); /*Busco la dirección MAC del next hop*/
  if (arpEntry != NULL) { /* Si la entrada ARP existe, usar la MAC correspondiente */
    memcpy(eHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, icmp_packet, icmp_size, iface_salida->name);
    
    printf("Paquete ICMP de error enviado\n");
    print_hdrs(icmp_packet, icmp_size);

    free(arpEntry); /* Liberar la entrada ARP tras su uso */
    free(icmp_packet); /* Liberar la memoria del paquete */

  } else { /* Si no está en la caché, encolar solicitud ARP */
    printf("No se encontró la entrada ARP para el paquete ICMP de error %d %d, encolando solicitud ARP...\n", type, code);
    struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache), arp_target_ip, icmp_packet, icmp_size, iface_salida->name);
    handle_arpreq(sr, arpReq);
  }
  return;
} /* -- sr_send_icmp_error_packet -- */














void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* 
  * - Obtener el cabezal IP y direcciones 
  * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento 
  * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
  * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply 
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

  /*
  * Verificar la longitud del paquete sea la suficiente para que contenga un cabezal IP
  */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    printf("Paquete demasiado corto para contener un encabezado IP.\n");
    return;
  }

  /*
  * Obtener el cabezal IP
  */
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /*
  * Verificar si el checksum del cabezal IP es correcto
  */
  uint16_t checksumOriginal = ipHdr->ip_sum;
  ipHdr->ip_sum = 0;
  uint16_t checksumCalculado = cksum(ipHdr, sizeof(sr_ip_hdr_t));
  if (checksumOriginal != checksumCalculado) {
    printf("Checksum IP no válido.\n");
    return;
  }

  /*
  * Extraer las direcciones de origen y destino
  */
  uint32_t ip_src = ipHdr->ip_src;
  uint32_t ip_dest = ipHdr->ip_dst;

  struct sr_if *ifac = sr_get_interface(sr, interface);
  if (ipHdr->ip_p == ip_protocol_ospfv2){
    sr_handle_pwospf_packet(sr, packet, len, ifac);
    return;
  }


  /* 
  * Verificar si el paquete es para alguna de mis interfaces 
  */
  /*struct sr_if *iface = sr_get_interface(sr, interface);*/
  struct sr_if *iface = sr_get_interface_given_ip(sr, ip_dest);
  if (iface != NULL && iface->ip == ip_dest) { /* el paquete es para mi interfaz */
    printf("Paquete para mí, procesando...\n");

    /*
    * Verificar si es un paquete ICMP
    */
    if (ipHdr->ip_p == ip_protocol_icmp) {

      /*
      * Extraer el cabezal ICMP
      */
      sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /*
      * Verificar si es un echo request
      */
      if (icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0) {
        printf("Recibido ICMP echo request, enviando echo reply...\n");

        /* 
        * Construir el echo reply
        */
        icmpHdr->icmp_type = 0;
        icmpHdr->icmp_code = 0;
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

        /*
        * Construir el paquete IP
        */
        ipHdr->ip_src = iface->ip;
        ipHdr->ip_dst = ip_src;
        ipHdr->ip_ttl = 64;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));

        /*
        * Construir el paquete Ethernet
        */
        struct sr_rt *bestMatch = buscar_en_tabla_enrutamiento(sr, ip_src);
        if (bestMatch == NULL) {
          printf("No se encontró una ruta");
          return;
        }
        struct sr_if *iface_salida = sr_get_interface(sr, bestMatch->interface);
        if (iface_salida == NULL) {
          printf("No se encontró la interfaz de salida");
          return;
        }
        memcpy(eHdr->ether_shost, iface_salida->addr, ETHER_ADDR_LEN); /*Seteo la dirección MAC de origen*/

        uint32_t arp_target_ip = (bestMatch->gw.s_addr == 0) ? ip_src : bestMatch->gw.s_addr;
        struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), arp_target_ip); /*Busco la dirección MAC del next hop*/
        if (arpEntry != NULL) { /* Si la entrada ARP existe, usar la MAC correspondiente */
          memcpy(eHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
          sr_send_packet(sr, packet, len, iface_salida->name);
          
          printf("Paquete echo reply enviado:\n");
          print_hdrs(packet, len);

          free(arpEntry); /* Liberar la entrada ARP tras su uso */

        } else { /* Si no está en la caché, encolar solicitud ARP */
          printf("No se encontró la entrada ARP, encolando solicitud ARP...\n");
          struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache), arp_target_ip, packet, len, iface_salida->name);
          handle_arpreq(sr, arpReq);

        }

      }

    } else { /* el paquete no es ICMP */
      /* 
      * Enviar un ICMP port unreachable
      */
      printf("Paquete no ICMP, enviando ICMP port unreachable...\n");
      sr_send_icmp_error_packet(3, 3, sr, ip_src, packet + sizeof(sr_ethernet_hdr_t));
    }

  } else { /* el paquete no es para mi interfaz (o no se encontró mi interfaz), reenviar */
    printf("Paquete no para mí, reenviando...\n");
    /*
    * Búscar en la tabla de enrutamiento
    */
    struct sr_rt *bestMatch = buscar_en_tabla_enrutamiento(sr, ip_dest);
    if (bestMatch == NULL) {
      printf("No se encontró una ruta, enviando ICMP net unreachable...\n");
      sr_send_icmp_error_packet(3, 0, sr, ip_src, packet + sizeof(sr_ethernet_hdr_t));
      return;
    }
    printf("Ruta encontrada:\n");

    /*
    * Actualizar el TTL
    */
    ipHdr->ip_ttl--;
    if (ipHdr->ip_ttl == 0) {
      printf("TTL agotado, enviando ICMP time exceeded...\n");
      sr_send_icmp_error_packet(11, 0, sr, ip_src, packet + sizeof(sr_ethernet_hdr_t));
      return;
    }

    /*
    * Actualizar checksum
    */
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));

    /*
    * Construir el paquete Ethernet
    */
    struct sr_if *iface_salida = sr_get_interface(sr, bestMatch->interface);
    if (iface_salida == NULL) {
      printf("No se encontró la interfaz de salida");
      return;
    }
    printf("Interfaz de salida encontrada:\n");
    memcpy(eHdr->ether_shost, iface_salida->addr, ETHER_ADDR_LEN); /*Seteo la dirección MAC de origen*/

    /*
    * Buscar en la caché ARP la dirección MAC correspondiente al next hop IP
    */
    uint32_t arp_target_ip = (bestMatch->gw.s_addr == 0) ? ip_dest : bestMatch->gw.s_addr;
    struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), arp_target_ip);
    if (arpEntry != NULL) { /* Si la entrada ARP existe, usar la MAC correspondiente */
      memcpy(eHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, iface_salida->name);
      
      printf("Paquete reenviado:\n");
      print_hdrs(packet, len);

      free(arpEntry); /* Liberar la entrada ARP tras su uso */

    } else { /* Si no está en la caché, encolar solicitud ARP */
      printf("No se encontró la entrada ARP, encolando solicitud ARP...\n");
      struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache), arp_target_ip, packet, len, iface_salida->name);
      handle_arpreq(sr, arpReq);

    }
  }
} /* -- sr_handle_ip_packet -- */



/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/



































/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     currPacket = currPacket->next;
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo el cabezal ARP */
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo las direcciones MAC */
  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  /* Obtengo las direcciones IP */
  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* Verifico si el paquete ARP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request) {  /* Si es un request ARP */
    printf("**** -> It is an ARP request.\n");

    /* Si el ARP request es para una de mis interfaces */
    if (myInterface != 0) {
      printf("***** -> ARP request is for one of my interfaces.\n");

      /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
      printf("****** -> Add MAC->IP mapping of sender to my ARP cache.\n");
      sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);

      /* Construyo un ARP reply y lo envío de vuelta */
      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *) myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eHdr->ether_dhost, (uint8_t *) senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP;
      arpHdr->ar_op = htons(arp_op_reply);

      /* Imprimo el cabezal del ARP reply creado */
      print_hdrs(packet, len);

      sr_send_packet(sr, packet, len, myInterface->name);
    }

    printf("******* -> ARP request processing complete.\n");

  } else if (op == arp_op_reply) {  /* Si es un reply ARP */

    printf("**** -> It is an ARP reply.\n");

    /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");
    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
    
    if (arpReq != NULL) { /* Si hay paquetes pendientes */

    	printf("****** -> Send outstanding packets.\n");
    	sr_arp_reply_send_pending_packets(sr, arpReq, (uint8_t *) myInterface->addr, (uint8_t *) senderHardAddr, myInterface);
    	sr_arpreq_destroy(&(sr->cache), arpReq);

    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */