/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 *
 * Descripción:
 * Este archivo contiene las funciones necesarias para el manejo de los paquetes
 * OSPF.
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>

#include "sr_utils.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_rt.h"
#include "pwospf_neighbors.h"
#include "pwospf_topology.h"
#include "dijkstra.h"

/*pthread_t hello_thread;*/
pthread_t g_hello_packet_thread;
pthread_t g_all_lsu_thread;
pthread_t g_lsu_thread;
pthread_t g_neighbors_thread;
pthread_t g_topology_entries_thread;
pthread_t g_rx_lsu_thread;
pthread_t g_dijkstra_thread;

pthread_mutex_t g_dijkstra_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in_addr g_router_id;
uint8_t g_ospf_multicast_mac[ETHER_ADDR_LEN];
struct ospfv2_neighbor* g_neighbors;
struct pwospf_topology_entry* g_topology;
uint16_t g_sequence_num;

/* -- Declaración de hilo principal de la función del subsistema pwospf --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Configura las estructuras de datos internas para el subsistema pwospf
 * y crea un nuevo hilo para el subsistema pwospf.
 *
 * Se puede asumir que las interfaces han sido creadas e inicializadas
 * en este punto.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    g_router_id.s_addr = 0;

    /* Defino la MAC de multicast a usar para los paquetes HELLO */
    g_ospf_multicast_mac[0] = 0x01;
    g_ospf_multicast_mac[1] = 0x00;
    g_ospf_multicast_mac[2] = 0x5e;
    g_ospf_multicast_mac[3] = 0x00;
    g_ospf_multicast_mac[4] = 0x00;
    g_ospf_multicast_mac[5] = 0x05;

    g_neighbors = NULL;

    g_sequence_num = 0;


    struct in_addr zero;
    zero.s_addr = 0;
    g_neighbors = create_ospfv2_neighbor(zero);
    g_topology = create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0);

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) { 
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
}

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} 

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Hilo principal del subsistema pwospf.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    sleep(5);

    struct sr_instance* sr = (struct sr_instance*)arg;

    /* Set the ID of the router */
    while(g_router_id.s_addr == 0)
    {
        struct sr_if* int_temp = sr->if_list;
        while(int_temp != NULL)
        {
            if (int_temp->ip > g_router_id.s_addr)
            {
                g_router_id.s_addr = int_temp->ip;
            }

            int_temp = int_temp->next;
        }
    }
    Debug("\n\nPWOSPF: Selecting the highest IP address on a router as the router ID\n");
    Debug("-> PWOSPF: The router ID is [%s]\n", inet_ntoa(g_router_id));


    Debug("\nPWOSPF: Detecting the router interfaces and adding their networks to the routing table\n");
    struct sr_if* int_temp = sr->if_list;
    while(int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr =  int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;

        if (check_route(sr, network) == 0)
        {
            Debug("-> PWOSPF: Adding the directly connected network [%s, ", inet_ntoa(network));
            Debug("%s] to the routing table\n", inet_ntoa(mask));
            sr_add_rt_entry(sr, network, gw, mask, int_temp->name, 1);
        }
        int_temp = int_temp->next;
    }
    
    Debug("\n-> PWOSPF: Printing the forwarding table\n");
    sr_print_routing_table(sr);


    printf("PWOSPF: Mostrar datos de las interfaces\n");
    /*imprimo valores de mis interfacez*/
    struct sr_if* iter = sr->if_list;
    while(iter != NULL){
        printf("Interface: %s\n", iter->name);
        /*printf("IP: %s\n", iter->ip);*/
        /*if (iter->mask != NULL){
            printf("Mascara: %s\n", iter->mask);
        } else {
            printf("Mascara: NULL\n");
        }*/
        if (iter->helloint != NULL){
            printf("HELLOINT: %d\n", iter->helloint);
        } else {
            printf("HELLOINT: NULL\n");
        }
        if (iter->neighbor_id != NULL){
            printf("Neighbor ID: %s\n", iter->neighbor_id);
        } else {
            printf("Neighbor ID: NULL\n");
        }
        if (iter->neighbor_ip != NULL){
            printf("Neighbor IP: %s\n", iter->neighbor_ip);
        } else {
            printf("Neighbor IP: NULL\n");
        }
        printf("----------------\n");

        iter = iter->next;
    }



    pthread_create(&g_hello_packet_thread, NULL, send_hellos, sr);
    pthread_create(&g_all_lsu_thread, NULL, send_all_lsu, sr);
    pthread_create(&g_neighbors_thread, NULL, check_neighbors_life, sr);
    pthread_create(&g_topology_entries_thread, NULL, check_topology_entries_age, sr);

    return NULL;
} /* -- run_ospf_thread -- */



















/***********************************************************************************
 * Métodos para el manejo de los paquetes HELLO y LSU
 * SU CÓDIGO DEBERÍA IR AQUÍ
 * *********************************************************************************/



















/*---------------------------------------------------------------------
 * Method: check_neighbors_life
 *
 * Chequea si los vecinos están vivos
 *
 *---------------------------------------------------------------------*/

void* check_neighbors_life(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    /* 
    Cada 1 segundo, chequea la lista de vecinos.
    */
    while(1){
        /* hace el chequeo cada un segundo de la vida de los vecinos con la funcion de chequeo ya implementada */
        printf("Chequeando la vida de los vecinos\n");
        struct ospfv2_neighbor* elim = check_neighbors_alive(g_neighbors);
        while(elim != NULL){
            struct sr_if* iter = sr->if_list;
            while(iter!=NULL){
                if(iter->neighbor_id == elim->neighbor_id.s_addr){
                    iter->neighbor_id = 0;
                    iter->neighbor_ip = 0;
                }
                iter = iter->next;
            }
            elim = elim->next;
        }
        free(elim);
        printf("Fin del chequeo de la vida de los vecinos\n");
        usleep(1000000);
    }
    return NULL;
} /* -- check_neighbors_life -- */



















/*---------------------------------------------------------------------
 * Method: check_topology_entries_age
 *
 * Check if the topology entries are alive 
 * and if they are not, remove them from the topology table
 *
 *---------------------------------------------------------------------*/

void* check_topology_entries_age(void* arg)
{
    printf("Chequeando la edad de las entradas de la topología\n");
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* 
    Cada 1 segundo, chequea el tiempo de vida de cada entrada
    de la topologia.
    Si hay un cambio en la topología, se llama a la función de Dijkstra
    en un nuevo hilo.
    Se sugiere también imprimir la topología resultado del chequeo.
    */
    bool cambio_topologia = 0;  
    while(1){
        printf("Entra al while de chequeo de la edad de las entradas de la topología\n");
        struct pwospf_topology_entry* entrada_actual = g_topology; /* g_topology es la tabla de topologia general definida en la inicializacion del pwospf */

        if(check_topology_age(entrada_actual)){ /* da 1 o sea true si se elimino una entrada antigua o sea cambio la tabla de topologia y hay que recalcular dijsktra*/
            /* Si hubo cambio en la topologia se debe ejecutar dijsktra en un nuevo hilo*/
            printf("CAMBIO TOPOLOGIA, SE EJECUTA dijkstra DE NUEVO.\n");
            /* Ejecuto Dijkstra en un nuevo hilo (run_dijkstra)*/
            struct dijkstra_param* dijkstra_param = ((struct dijkstra_param*)(malloc(sizeof(struct dijkstra_param))));
            dijkstra_param->sr = sr;
            dijkstra_param->topology = g_topology;
            dijkstra_param->rid = g_router_id;
            dijkstra_param->mutex = g_dijkstra_mutex;

            pthread_t dijkstra_thread;
            pthread_create(&dijkstra_thread, NULL, (void*)run_dijkstra, dijkstra_param);/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!ACA NO SE PASA SR, ES UN DIJKSTRA_PARAM*/
            pthread_detach(dijkstra_thread);
            cambio_topologia = 0; /* "reinicia" la variable para la siguiente ejecucion del while */
        }
        /* Imprimimos la tabla de la topologia para chequear*/
        print_topolgy_table(g_topology);
        printf("Fin del chequeo de la edad de las entradas de la topología\n");

        usleep(1000000); /* chequea cada 1 segundo */
    }

    return NULL;
} /* -- check_topology_entries_age -- */



















/*---------------------------------------------------------------------
 * Method: send_hellos
 *
 * Para cada interfaz y cada helloint segundos, construye mensaje 
 * HELLO y crea un hilo con la función para enviar el mensaje.
 *
 *---------------------------------------------------------------------*/


void* send_hellos(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    
    /* While true */
    while(1)
    {
        usleep(1000000);
        printf("----------------ENVIANDO HELLOs-------------------\n");
        /* Se ejecuta cada 1 segundo */

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        printf("BLOQUEANDO HELLO\n");
        pwospf_lock(sr->ospf_subsys);

        /* Chequeo todas las interfaces para enviar el paquete HELLO */
            /* Cada interfaz matiene un contador en segundos para los HELLO*/
            /* Reiniciar el contador de segundos para HELLO */
        struct sr_if* ifaz_actual = sr->if_list;
        while(ifaz_actual != NULL){
            if (ifaz_actual->helloint <= 0){
                /*enviar hello packet*/
                printf("Encontro una interfaz, envia hello\n");
                powspf_hello_lsu_param_t* nuevo = malloc(sizeof(powspf_hello_lsu_param_t));
                nuevo->interface = ifaz_actual;
                nuevo->sr = sr;
                send_hello_packet(nuevo);
                free(nuevo);
                /* reinicio el contador del mensaje HELLO de la interfaz*/
                ifaz_actual->helloint = OSPF_DEFAULT_HELLOINT;
            }else{
                /*Si no se decrementa el timer en 1 ya que paso un segundo de la ultima recorrida*/
                ifaz_actual->helloint -= 1;
            }
            ifaz_actual = ifaz_actual->next;
        }
        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
        printf("DESBLOQUEADO HELLO\n");
    };

    return NULL;
} /* -- send_hellos -- */



















/*---------------------------------------------------------------------
 * Method: send_hello_packet
 *
 * Recibe un mensaje HELLO, agrega cabezales y lo envía por la interfaz
 * correspondiente.
 *
 *---------------------------------------------------------------------*/

void* send_hello_packet(void* arg)
{
    printf("Enviando HELLO\n");
    powspf_hello_lsu_param_t* hello_param = ((powspf_hello_lsu_param_t*)(arg));

    Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", hello_param->interface->name);

    int largo_hello_packet = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t); 
    uint8_t *hello_packet = malloc(largo_hello_packet); 
    
    struct sr_if *ifaz_salida = hello_param->interface;
    /* Seteo la dirección MAC de multicast para la trama a enviar */
    /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
    /* Seteo el ether_type en el cabezal Ethernet */
    sr_ethernet_hdr_t *cabezal_ethernet = (sr_ethernet_hdr_t *)hello_packet;
    memcpy(cabezal_ethernet->ether_shost, ifaz_salida->addr, ETHER_ADDR_LEN);
    memcpy(cabezal_ethernet->ether_dhost, g_ospf_multicast_mac, ETHER_ADDR_LEN);
    cabezal_ethernet->ether_type = htons(ethertype_ip);

    /* Inicializo cabezal IP */
    /* Seteo el protocolo en el cabezal IP para ser el de OSPF (89) */
    /* Seteo IP origen con la IP de mi interfaz de salida */
    /* Seteo IP destino con la IP de Multicast dada: OSPF_AllSPFRouters  */
    /* Calculo y seteo el chechsum IP*/

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(hello_packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t)); 
    ip_hdr->ip_id = htons(0);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_ospfv2;
    ip_hdr->ip_src = ifaz_salida->ip;
    ip_hdr->ip_dst = htonl(OSPF_AllSPFRouters);
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
    
    /* Inicializo cabezal de PWOSPF con version 2 y tipo HELLO */
    
    /* Seteo el Router ID con mi ID*/
    /* Seteo el Area ID en 0 */
    /* Seteo el Authentication Type y Authentication Data en 0*/
    /* Seteo máscara con la máscara de mi interfaz de salida */
    /* Seteo Hello Interval con OSPF_DEFAULT_HELLOINT */
    /* Seteo Padding en 0*/

    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t*)(hello_packet + sizeof(struct sr_ip_hdr) + sizeof(sr_ethernet_hdr_t));
    ospf_hdr->rid = g_router_id.s_addr;
    ospf_hdr->aid = 0;
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0;
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_HELLO;
    
    /* CHEQUEAR SI ESTA TODO BIEN REFERENCIADO FIJANDOSE EN LO QUE YA HICIMOS EN router.c*/

    ospfv2_hello_hdr_t *hello_hdr = (ospfv2_hello_hdr_t*)(hello_packet + sizeof(struct sr_ip_hdr) + sizeof(sr_ethernet_hdr_t) + sizeof(ospfv2_hdr_t));
    hello_hdr->nmask = ifaz_salida->mask;
    hello_hdr->helloint = OSPF_DEFAULT_HELLOINT;
    hello_hdr->padding = 0;
    /* Creo el paquete a transmitir */
   
    /* Calculo y actualizo el checksum del cabezal OSPF */
    ospf_hdr->csum = 0;
    ospf_hdr->csum = cksum(ospf_hdr,sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));
    
    sr_send_packet(hello_param->sr,hello_packet,largo_hello_packet,ifaz_salida->name);
    /* Envío el paquete HELLO */
    /* Imprimo información del paquete HELLO enviado */

    struct in_addr ipsource;
    ipsource.s_addr = ip_hdr->ip_src;
    struct in_addr mask;
    mask.s_addr = hello_hdr->nmask;
    
    Debug("-> PWOSPF: Sending HELLO Packet of length = %d, out of the interface: %s\n", largo_hello_packet, hello_param->interface->name);
    Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));
    Debug("      [Router IP = %s]\n", inet_ntoa(ipsource));
    Debug("      [Network Mask = %s]\n", inet_ntoa(mask));
    
    free(hello_packet); /* VA ESTO???? */
    return NULL;
} /* -- send_hello_packet -- */



















/*---------------------------------------------------------------------
 * Method: send_all_lsu
 *
 * Construye y envía LSUs cada 30 segundos
 *
 *---------------------------------------------------------------------*/

void* send_all_lsu(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* while true*/
    while(1)
    {
        usleep(OSPF_DEFAULT_LSUINT * 1000000);
        /* Se ejecuta cada OSPF_DEFAULT_LSUINT segundos */
        printf("----------------ENIVANDO TODOS LOS LSU-------------\n");
        

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        
        printf("BLOQUEADO LSU\n");
        pwospf_lock(sr->ospf_subsys);
        
        /* Recorro todas las interfaces para enviar el paquete LSU */
            /* Si la interfaz tiene un vecino, envío un LSU */
        struct sr_if *iterator = sr->if_list;
        while(iterator != NULL){ /* Esta bien este chequeo de si tiene vecino?? */
            if(iterator->neighbor_id != NULL && iterator->neighbor_id != 0){ /* Si tiene un vecino*/
                printf("Envia LSU a un vecino \n");
                powspf_hello_lsu_param_t* lsu_param = malloc(sizeof(powspf_hello_lsu_param_t));
                lsu_param->sr = sr;
                lsu_param->interface = iterator;
                send_lsu(lsu_param);
            }
            iterator = iterator->next;
        }

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);        
        printf("DESBLOQUEADO LSU\n");
    };

    return NULL;
} /* -- send_all_lsu -- */



















/*---------------------------------------------------------------------
 * Method: send_lsu
 *
 * Construye y envía paquetes LSU a través de una interfaz específica
 *
 *---------------------------------------------------------------------*/

void* send_lsu(void* arg)
{
    printf("Enviando LSU\n");
    powspf_hello_lsu_param_t* lsu_param = ((powspf_hello_lsu_param_t*)(arg));

    /* Solo envío LSUs si del otro lado hay un router*/
    if (lsu_param->interface->neighbor_id == NULL || lsu_param->interface->neighbor_id == 0){
        return NULL;
    }
    
    /* Construyo el LSU */
    Debug("\n\nPWOSPF: Constructing LSU packet\n");
    
    struct sr_rt *iteratort = lsu_param->sr->routing_table;
    int i = 0;
    while (iteratort != NULL){
        if(iteratort->admin_dst <= 1){
            i++;
        }
        iteratort = iteratort->next;
    }    

    int largo_lsu_packet = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (i * sizeof(ospfv2_lsa_t));
    uint8_t *lsu_packet = malloc(largo_lsu_packet); 

    struct sr_if *ifaz_salida = lsu_param->interface;

    /* Inicializo cabezal Ethernet */
    /* Dirección MAC destino la dejo para el final ya que hay que hacer ARP */
    sr_ethernet_hdr_t *cabezal_ethernet = (sr_ethernet_hdr_t *)lsu_packet;
    memcpy(cabezal_ethernet->ether_shost, ifaz_salida->addr, ETHER_ADDR_LEN);
    cabezal_ethernet->ether_type = htons(ethertype_ip);

    /* Inicializo cabezal IP*/
    /* La IP destino es la del vecino contectado a mi interfaz*/
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(lsu_packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (i * sizeof(ospfv2_lsa_t))); 
    ip_hdr->ip_id = htons(0);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_ospfv2;
    ip_hdr->ip_src = ifaz_salida->ip;
    ip_hdr->ip_dst = ifaz_salida->neighbor_ip;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

    /* Inicializo cabezal de OSPF*/
    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t*)(lsu_packet + sizeof(struct sr_ip_hdr) + sizeof(sr_ethernet_hdr_t));
    ospf_hdr->rid = g_router_id.s_addr;
    ospf_hdr->aid = 0;
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0;
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_LSU;

    /* Seteo el número de secuencia y avanzo*/
    /* Seteo el TTL en 64 y el resto de los campos del cabezal de LSU */
    /* Seteo el número de anuncios con la cantidad de rutas a enviar. Uso función count_routes */
    ospfv2_lsu_hdr_t *lsu_hdr = (ospfv2_lsu_hdr_t*)(lsu_packet + sizeof(struct sr_ip_hdr) + sizeof(sr_ethernet_hdr_t) + sizeof(ospfv2_hdr_t));
    lsu_hdr->seq = g_sequence_num;
    g_sequence_num++;
    lsu_hdr->ttl = 64;
    lsu_hdr->num_adv = count_routes(lsu_param->sr);

    /* Creo el paquete y seteo todos los cabezales del paquete a transmitir */

    /* Creo cada LSA iterando en las enttadas de la tabla */
        /* Solo envío entradas directamente conectadas y agreagadas a mano*/
        /* Creo LSA con subnet, mask y routerID (id del vecino de la interfaz)*/
    iteratort = lsu_param->sr->routing_table;
    int j = 0;
    while (iteratort != NULL){
        if(iteratort->admin_dst <= 1){
            ospfv2_lsa_t *LSA = (ospfv2_lsa_t *)(lsu_packet + sizeof(struct sr_ip_hdr) + sizeof(sr_ethernet_hdr_t) + sizeof(ospfv2_hdr_t)+ sizeof(ospfv2_lsu_hdr_t)+(j * sizeof(ospfv2_lsa_t)));
            struct sr_if *if_act = sr_get_interface(lsu_param->sr,iteratort->interface);
            struct in_addr aux;
            aux.s_addr = if_act->mask;
            Debug(" [ -MASCARA DE UNO DE LOS LSA: %s]\n", inet_ntoa(aux));
            aux.s_addr = (if_act->ip & if_act->mask);
            Debug(" [ -SUBRED DE UNO DE LOS LSA: %s]\n", inet_ntoa(aux));
            LSA->mask = if_act->mask;
            LSA->subnet = (if_act->ip & if_act->mask);
            LSA->rid = if_act->neighbor_id;
            j++;
        }
        iteratort = iteratort->next;
    }

    /* Calculo el checksum del paquete LSU */
    ospf_hdr->csum = 0;
    ospf_hdr->csum = cksum(ospf_hdr,sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (j * sizeof(ospfv2_lsa_t)));
    
    /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
    /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(lsu_param->sr->cache),ip_hdr->ip_dst);
    if(arp_entry != NULL){
        printf("Direccion MAC encontrada, reenviando paquete...\n");
          memcpy(cabezal_ethernet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
          
          /** 
          * Enviar el paquete
          */
          sr_send_packet(lsu_param->sr, lsu_packet, largo_lsu_packet, ifaz_salida->name);
          
          /** 
          * Liberar la entrada ARP tras su uso
          */
          free(arp_entry);
    } else { 
    /* Si no está en la caché, encolar solicitud ARP */
        printf("No se encontró la entrada ARP, encolando solicitud ARP...\n");
        struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(lsu_param->sr->cache), ip_hdr->ip_dst, lsu_packet, largo_lsu_packet, ifaz_salida->name);
        handle_arpreq(lsu_param->sr, arpReq);
        return;
    }
    printf("IMPRIMIMOS HEADER DEL PAQUETE OSPF DE TIPO LSU: \n");
    print_hdr_ospf(ospf_hdr);
    printf("Se envio LSU.\n");
    /* Libero memoria */
    printf("Libero memoria del paquete LSU\n");
    free(lsu_packet);
    printf("Libero memoria del parametro\n");
    free(lsu_param);
    return NULL;
} /* -- send_lsu -- */




/*
-----------------------------------------------------------------------
Destination       Gateway           Subnet Mask       Iface   Admin Dis
-----------------------------------------------------------------------
10.0.2.0          0.0.0.0           255.255.255.0     eth3    1
10.0.0.0          0.0.0.0           255.255.255.0     eth2    1
100.0.0.0         0.0.0.0           255.255.255.0     eth1    1
200.0.0.0         10.0.0.2          255.255.255.0     eth2    110
10.0.1.0          10.0.0.2          255.255.255.0     eth2    110
200.100.0.0       10.0.0.2          255.255.255.0     eth2    110

REENVIO:
---------------------------------------------
Destination     Gateway         Mask    Iface
10.0.2.0        0.0.0.0     255.255.255.0   eth3
10.0.0.0        0.0.0.0     255.255.255.0   eth2
100.0.0.0       0.0.0.0     255.255.255.0   eth1
200.0.0.0       10.0.0.2    255.255.255.0   eth2
10.0.1.0        10.0.0.2    255.255.255.0   eth2
200.100.0.0     10.0.2.2    255.255.255.0   eth3
100.0.0.1       100.0.0.1   255.255.255.255 eth1
---------------------------------------------

CON SU BINARIO:
-----------------------------------------------------------------------
Destination       Gateway           Subnet Mask       Iface   Admin Dis
-----------------------------------------------------------------------
10.0.2.0          0.0.0.0           255.255.255.0     eth3    1
10.0.0.0          0.0.0.0           255.255.255.0     eth2    1
100.0.0.0         0.0.0.0           255.255.255.0     eth1    1
200.0.0.0         10.0.0.2          255.255.255.0     eth2    110
10.0.1.0          10.0.2.2          255.255.255.0     eth3    110
200.100.0.0       10.0.2.2          255.255.255.0     eth3    110
*/














/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_hello_packet
 *
 * Gestiona los paquetes HELLO recibidos
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_hello_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    printf("ENTRO A LA FUNCION DE MANEJO DE HELLO\n");
    /* Obtengo información del paquete recibido */
    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));
    ospfv2_hdr_t* ospfv2_hdr = ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    ospfv2_hello_hdr_t* ospfv2_hello_hdr = ((ospfv2_hello_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t)));

    struct in_addr neighbor_id;
    neighbor_id.s_addr = ospfv2_hdr->rid;
    struct in_addr neighbor_ip;
    neighbor_ip.s_addr = ip_hdr->ip_src;
    struct in_addr net_mask;
    net_mask.s_addr = ospfv2_hello_hdr->nmask;
    uint16_t hello_int = ospfv2_hello_hdr->helloint; /* ver esto uint8 o uint16?*/
    struct sr_if *iter = sr->if_list;
    struct sr_if *ifaz_entrada;
    while(iter != NULL){
        if(strcmp(iter->name, rx_if->name) == 0){
            ifaz_entrada = iter;
        }
        iter = iter->next;
    }

    /* Imprimo info del paquete recibido*/
    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
    Debug("      [Neighbor IP = %s]\n", inet_ntoa(neighbor_ip));
    Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));
    
    
    /* Chequeo checksum */
    uint16_t checksum_viejo = ospfv2_hdr->csum;
    uint64_t audata_viejo = ospfv2_hdr->audata;
    ospfv2_hdr->audata = 0;
    uint16_t checksum_nuevo = ospfv2_cksum(ospfv2_hdr, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t)); /* va el cabezal hello?*/

    printf("Chequeo del checksum\n");
    if(checksum_viejo != checksum_nuevo){
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }


    printf("Chequeo de la máscara de red\n");
    /* Chequeo de la máscara de red */
    if (ifaz_entrada->mask != NULL && ospfv2_hello_hdr->nmask != ifaz_entrada->mask){
        struct in_addr aux;
        aux.s_addr = ifaz_entrada->mask;
        printf("Mascara de red recibida: %s\n", inet_ntoa(net_mask));
        printf("Mascara de red de la interfaz: %s\n", inet_ntoa(aux));
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");
        return;
    }

    printf("chequeo del intervalo de HELLO\n");
    /* Chequeo del intervalo de HELLO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
    if (ospfv2_hello_hdr->helloint != OSPF_DEFAULT_HELLOINT)/*(rx_if->helloint != NULL && hello_int != rx_if->helloint)*/{
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");
        return;
    }

    /* Seteo el vecino en la interfaz por donde llegó y actualizo la lista de vecinos */

    /*refresh_neighbors_alive(g_neighbors, neig);*/ 
    /*Falta saber si es un nuevo vecino!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

    printf("Busco a quien envió el hello\n");
    struct ospfv2_neighbor* ptr = g_neighbors;
    while(ptr != NULL)
    {
        if (ptr->neighbor_id.s_addr == neighbor_id.s_addr)
        {
            Debug("-> PWOSPF: Refreshing the neighbor, [ID = %s] in the alive neighbors table\n", inet_ntoa(neighbor_id));
            ptr->alive = OSPF_NEIGHBOR_TIMEOUT;
            return;
        }
        ptr = ptr->next;
    }

    /* Si es un nuevo vecino, debo enviar LSUs por todas mis interfaces*/
    Debug("-> PWOSPF: Adding the neighbor, [ID = %s] to the alive neighbors table\n", inet_ntoa(neighbor_id));
    add_neighbor(g_neighbors, create_ospfv2_neighbor(neighbor_id));

    iter = sr->if_list;
    while(iter != NULL){
        if(strcmp(iter->name, rx_if->name) == 0){
            printf("Voy a agregar el vecino a la interfaz\n");
            iter->neighbor_id = neighbor_id.s_addr;
            iter->neighbor_ip = neighbor_ip.s_addr;
            
            iter->mask = net_mask.s_addr;
            iter->helloint = OSPF_DEFAULT_HELLOINT;
        }
        iter = iter->next;
    }
    /* Recorro todas las interfaces para enviar el paquete LSU*/
    struct sr_if *iterator = sr->if_list;
    while(iterator != NULL){
        if(iterator->neighbor_id != NULL && iterator->neighbor_id != 0){
            /* Si la interfaz tiene un vecino, envío un LSU*/
            printf("Envia LSU a un vecino \n");
            powspf_hello_lsu_param_t* lsu_param = malloc(sizeof(powspf_hello_lsu_param_t));
            lsu_param->sr = sr;
            lsu_param->interface = iterator;
            send_lsu(lsu_param);
        }
        iterator = iterator->next;
    }

    printf("Fin de la función de manejo de HELLO\n");
    return;

} /* -- sr_handle_pwospf_hello_packet -- */



















/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_lsu_packet
 *
 * Gestiona los paquetes LSU recibidos y actualiza la tabla de topología
 * y ejecuta el algoritmo de Dijkstra
 *
 *---------------------------------------------------------------------*/

void* sr_handle_pwospf_lsu_packet(void* arg)
{
    printf("ENTRO A LA FUNCION DE MANEJO DE LSU\n");
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(arg));

    /* Obtengo el vecino que me envió el LSU*/
    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((rx_lsu_param->packet) + sizeof(sr_ethernet_hdr_t)));
    ospfv2_hdr_t* ospfv2_hdr = ((ospfv2_hdr_t*)((rx_lsu_param->packet) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    ospfv2_lsu_hdr_t* ospfv2_lsu_hdr = ((ospfv2_lsu_hdr_t*)((rx_lsu_param->packet) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t)));

    struct in_addr next_hop_id;
    next_hop_id.s_addr = ospfv2_hdr->rid;
    struct in_addr next_hop_ip; 
    next_hop_ip.s_addr = ip_hdr->ip_src;  
    
    /* Imprimo info del paquete recibido*/
    Debug("-> PWOSPF: Detecting LSU Packet from [Neighbor ID = %s, IP = %s]\n", inet_ntoa(next_hop_id), inet_ntoa(next_hop_ip));
    
    /* Chequeo checksum */
    uint16_t checksum_viejo = ospfv2_hdr->csum;
    uint64_t audata_viejo = ospfv2_hdr->audata;
    ospfv2_hdr->audata = 0;
    uint16_t checksum_nuevo = ospfv2_cksum(ospfv2_hdr, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (ospfv2_lsu_hdr->num_adv * sizeof(ospfv2_lsa_t)));

    if(checksum_viejo != checksum_nuevo){
        Debug("-> PWOSPF: LSU Packet dropped, invalid checksum\n");
        return NULL;
    }

    /* Obtengo el Router ID del router originario del LSU y chequeo si no es mío*/
    if(g_router_id.s_addr == next_hop_id.s_addr){
        Debug("-> PWOSPF: LSU Packet dropped, originated by this router\n");
        return NULL;
    }
    

    /* Obtengo el número de secuencia y uso check_sequence_number para ver si ya lo recibí desde ese vecino*/
    if(!check_sequence_number(g_topology, next_hop_id, ospfv2_lsu_hdr->seq)){
        Debug("-> PWOSPF: LSU Packet dropped, repeated sequence number\n");
        return NULL;
    }

    /* Itero en los LSA que forman parte del LSU. Para cada uno, actualizo la topología.*/
    Debug("-> PWOSPF: Processing LSAs and updating topology table\n");
    unsigned int i;
    for (i=0; i < ospfv2_lsu_hdr->num_adv; i++){
        ospfv2_lsa_t* lsa = ((ospfv2_lsa_t*)((rx_lsu_param->packet) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (i * sizeof(ospfv2_lsa_t))));
        
        /* Obtengo subnet */
        struct in_addr net_num;
        net_num.s_addr = lsa->subnet;

        struct in_addr net_mask;
        net_mask.s_addr = lsa->mask;

        /* Obtengo vecino */
        struct in_addr neighbor_id;
        neighbor_id.s_addr = lsa->rid;

        /* Imprimo info de la entrada de la topología */
        Debug("      [Subnet = %s]", inet_ntoa(net_num));
        Debug("      [Mask = %s]", inet_ntoa(net_mask));
        Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
        
        /* LLamo a refresh_topology_entry*/
        refresh_topology_entry(g_topology, next_hop_id, net_num, net_mask, neighbor_id, next_hop_ip, ospfv2_lsu_hdr->seq); /*NO SABEMOS SI VA EL NEXT_HOP_IP O QUE?????????????????????????????*/
    }

    /* Imprimo la topología */
    Debug("\n-> PWOSPF: Printing the topology table\n");
    print_topolgy_table(g_topology);

/*
    struct dijkstra_param* dijkstra_param = ((struct dijkstra_param*)(malloc(sizeof(struct dijkstra_param))));
    dijkstra_param->sr = sr;
    dijkstra_param->topology = g_topology;
    dijkstra_param->rid = g_router_id;
    dijkstra_param->mutex = g_dijkstra_mutex;

    pthread_t dijkstra_thread;
    pthread_create(&dijkstra_thread, NULL, (void*)run_dijkstra, dijkstra_param);
    pthread_detach(dijkstra_thread);
*/


    /* Ejecuto Dijkstra en un nuevo hilo (run_dijkstra)*/
    struct dijkstra_param* dijkstra_param = ((struct dijkstra_param*)(malloc(sizeof(struct dijkstra_param))));
    dijkstra_param->sr = rx_lsu_param->sr;
    dijkstra_param->topology = g_topology;
    dijkstra_param->rid = g_router_id;
    dijkstra_param->mutex = g_dijkstra_mutex;

    printf("EJECUTAMOS DIJSKTRA Y SE DEBERIA DE IMPRIMIR LA TABLA DE ENRUTAMIENTO.\n");
    pthread_create(&g_dijkstra_thread, NULL, run_dijkstra, dijkstra_param);

    /* Flooding del LSU por todas las interfaces menos por donde me llegó */
    struct sr_if *ifaz_actual = rx_lsu_param->sr->if_list;
    while(ifaz_actual != NULL){
        if(ifaz_actual->name != rx_lsu_param->rx_if->name && ifaz_actual->neighbor_id != NULL && ifaz_actual->neighbor_id != 0){
            
            /*Pido memoria para el paquete*/
            uint8_t *lsu_packet = malloc(rx_lsu_param->length);
            memcpy(lsu_packet, rx_lsu_param->packet, rx_lsu_param->length);

            /* Ajusto cabezal OSPF: checksum y TTL*/
            ospfv2_hdr_t* ospfv2_hdr = ((ospfv2_hdr_t*)(lsu_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
            ospfv2_lsu_hdr_t* ospfv2_lsu_hdr = ((ospfv2_lsu_hdr_t*)(lsu_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t)));
            ospfv2_lsu_hdr->ttl--;
            ospfv2_hdr->csum = 0;
            ospfv2_hdr->csum = cksum(ospfv2_hdr, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (ospfv2_lsu_hdr->num_adv * sizeof(ospfv2_lsa_t))); /*ver si va solo el header de ospf sin lsu!!!!!!!!!! */
    
            /* Ajusto paquete IP, origen y checksum*/
            sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)(lsu_packet + sizeof(sr_ethernet_hdr_t)));
            ip_hdr->ip_src = ifaz_actual->ip;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            /* Seteo MAC de origen */
            sr_ethernet_hdr_t* eth_hdr = ((sr_ethernet_hdr_t*)lsu_packet);
            memcpy(eth_hdr->ether_shost, ifaz_actual->addr, ETHER_ADDR_LEN);

            struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(rx_lsu_param->sr->cache), ifaz_actual->neighbor_ip);
            if (arpEntry != NULL) { /* Si la entrada ARP existe, usar la MAC correspondiente */
                memcpy(eth_hdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
                sr_send_packet(rx_lsu_param->sr, lsu_packet, rx_lsu_param->length, ifaz_actual->name);
                
                printf("Paquete reenviado:\n");
                print_hdrs(lsu_packet, rx_lsu_param->length);

                free(arpEntry); /* Liberar la entrada ARP tras su uso */
                /* Libero memoria */
                free(lsu_packet);

            } else { /* Si no está en la caché, encolar solicitud ARP */
                printf("No se encontró la entrada ARP, encolando solicitud ARP...\n");
                struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(rx_lsu_param->sr->cache), ifaz_actual->neighbor_ip, lsu_packet, rx_lsu_param->length, ifaz_actual->name);
                handle_arpreq(rx_lsu_param->sr, arpReq);
            }
        }
        ifaz_actual = ifaz_actual->next;
    }

    return NULL;
} /* -- sr_handle_pwospf_lsu_packet -- */



















/**********************************************************************************
 * SU CÓDIGO DEBERÍA TERMINAR AQUÍ
 * *********************************************************************************/



















/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_packet
 *
 * Gestiona los paquetes PWOSPF
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    /*Si aún no terminó la inicialización, se descarta el paquete recibido*/
    if (g_router_id.s_addr == 0) {
       return;
    }

    ospfv2_hdr_t* rx_ospfv2_hdr = ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(malloc(sizeof(powspf_rx_lsu_param_t))));

    Debug("-> PWOSPF: Detecting PWOSPF Packet\n");
    Debug("      [Type = %d]\n", rx_ospfv2_hdr->type);

    switch(rx_ospfv2_hdr->type)
    {
        case OSPF_TYPE_HELLO:
            sr_handle_pwospf_hello_packet(sr, packet, length, rx_if);
            break;
        case OSPF_TYPE_LSU:
            rx_lsu_param->sr = sr;
            unsigned int i;
            for (i = 0; i < length; i++)
            {
                rx_lsu_param->packet[i] = packet[i];
            }
            rx_lsu_param->length = length;
            rx_lsu_param->rx_if = rx_if;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            pthread_t pid;
            pthread_create(&pid, &attr, sr_handle_pwospf_lsu_packet, rx_lsu_param);
            break;
    }
} /* -- sr_handle_pwospf_packet -- */
