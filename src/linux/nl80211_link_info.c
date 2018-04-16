
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2012 Fox-IT B.V. <opensource@fox-it.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#ifdef __linux__
#ifdef LINUX_NL80211 /* Optional - not supported on all platforms */

#include <stdlib.h>
#include <stdbool.h>

//#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/nl80211.h>
#include <linux/if_ether.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/addr.h>
#include <netlink/route/neighbour.h>

#include "nl80211_link_info.h"
#include "lq_plugin_ffeth_nl80211.h"
#include "interfaces.h"
#include "olsr.h"
#include "log.h"
#include "fpm.h"


// Static values for testing
#define REFERENCE_BANDWIDTH_MBIT_SEC 54

#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
#define nl_sock nl_handle
static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *sock)
{
	nl_handle_destroy(sock);
}
#endif

#define ASSERT_NOT_NULL(PARAM) do { \
		if ((PARAM) == NULL) { \
			olsr_exit("Pointer value for '" #PARAM "' cannot be NULL", EXIT_FAILURE); \
		} \
	} while (0)

struct nl80211_link_info_context {
	int *finish;
	struct lq_nl80211_data **nl80211;
};

static int netlink_id = 0;
static struct nl_sock *gen_netlink_socket = NULL; // Socket for NL80211
static struct nl_sock *rt_netlink_socket = NULL; // Socket for ARP cache

struct rtnl_neigh * my_rtnl_neigh_get(struct nl_cache *cache, int ifindex,
                                      struct nl_addr *dst)
{
    struct rtnl_neigh *neigh;

    neigh = (struct rtnl_neigh *)nl_cache_get_first (cache);
    while (neigh) {
        if (rtnl_neigh_get_ifindex (neigh) == ifindex) {
            struct nl_addr *d;

            d = rtnl_neigh_get_dst (neigh);
            if (d && !nl_addr_cmp(d, dst)) {
                nl_object_get((struct nl_object *) neigh);
                return neigh;
            }
         }
         neigh = (struct rtnl_neigh *)nl_cache_get_next ((struct nl_object *)neigh);
    }
    return NULL;
}



/**
 * Opens two netlink connections to the Linux kernel. One connection to retreive
 * wireless 802.11 information and one for querying the ARP cache.
 */
static void connect_netlink(void) {
	if ((gen_netlink_socket = nl_socket_alloc()) == NULL) {
		olsr_exit("Failed allocating memory for netlink socket", EXIT_FAILURE);
	}

	if (genl_connect(gen_netlink_socket) != 0) {
		olsr_exit("Failed to connect with generic netlink", EXIT_FAILURE);
	}
	
	if ((netlink_id = genl_ctrl_resolve(gen_netlink_socket, "nl80211")) < 0) {
		olsr_exit("Failed to resolve netlink nl80211 module", EXIT_FAILURE);
	}

	if ((rt_netlink_socket = nl_socket_alloc()) == NULL) {
		olsr_exit("Failed allocating memory for netlink socket", EXIT_FAILURE);
	}

	if ((nl_connect(rt_netlink_socket, NETLINK_ROUTE)) != 0) {
		olsr_exit("Failed to connect with NETLINK_ROUTE", EXIT_FAILURE);
	}
}

static int parse_nl80211_message(struct nl_msg *msg, void *arg) {
	struct nl80211_link_info_context *context = (struct nl80211_link_info_context *) arg;
	struct genlmsghdr *header = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attributes[NL80211_ATTR_MAX + 1];
	struct nlattr *station_info[NL80211_STA_INFO_MAX + 1];
	struct nlattr *rate_info[NL80211_RATE_INFO_MAX + 1];
	struct lq_nl80211_data *lq_data = NULL;
	uint8_t signal;
	uint8_t signal_avg;
	uint16_t bandwidth;

	static struct nla_policy station_attr_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 }, // Last activity from remote station (msec)
		[NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 }, // Signal strength of last received PPDU (dBm)
		[NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED }, // Transmit bitrate to this station
	};
	static struct nla_policy station_rate_policy[NL80211_RATE_INFO_MAX + 1] = {
		[NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 }, // Bitrate (100kbit/s)
	};

	ASSERT_NOT_NULL(msg);
	ASSERT_NOT_NULL(context);

	if (nla_parse(attributes, NL80211_ATTR_MAX, genlmsg_attrdata(header, 0), genlmsg_attrlen(header, 0), NULL) != 0) {
		*(context->finish) = 1;
		return NL_STOP;
	}

	if (!attributes[NL80211_ATTR_STA_INFO]) {
		olsr_syslog(OLSR_LOG_INFO, "Did not receive station info in netlink reply");
		return NL_SKIP;
	}

	if (nla_parse_nested(station_info, NL80211_STA_INFO_MAX, attributes[NL80211_ATTR_STA_INFO],
				station_attr_policy) < 0) {
		*(context->finish) = 1;
		return NL_STOP;
	}
	if (nla_parse_nested(rate_info, NL80211_RATE_INFO_MAX, station_info[NL80211_STA_INFO_TX_BITRATE],
				station_rate_policy) < 0) {
		*(context->finish) = 1;
		return NL_STOP;
	}

	if (nla_len(attributes[NL80211_ATTR_MAC]) != ETHER_ADDR_LEN) {
		olsr_syslog(OLSR_LOG_ERR, "Attribute NL80211_ATTR_MAC length is not equal to ETHER_ADDR_LEN");
		*(context->finish) = 1;
		return NL_STOP;
	}

	if (station_info[NL80211_STA_INFO_SIGNAL]) {
		signal = nla_get_u8(station_info[NL80211_STA_INFO_SIGNAL]);
	}


	if (station_info[NL80211_STA_INFO_SIGNAL_AVG]) {
		signal_avg = nla_get_u8(station_info[NL80211_STA_INFO_SIGNAL_AVG]);
	}

	if (rate_info[NL80211_RATE_INFO_BITRATE]) {
		bandwidth = nla_get_u16(rate_info[NL80211_RATE_INFO_BITRATE]);
	}

	if (bandwidth != 0 || signal != 0) {
		lq_data = olsr_malloc(sizeof(struct lq_nl80211_data), "new lq_nl80211_data struct");
		memcpy(lq_data->mac, nla_data(attributes[NL80211_ATTR_MAC]), ETHER_ADDR_LEN);
		lq_data->signal = signal;
		lq_data->signal_avg = signal_avg;
		lq_data->bandwidth = bandwidth;
		lq_data->next = NULL;

		if (context->nl80211 == NULL) { // Linked list does not exist yet
			*(context->nl80211) = lq_data;
		} else { // Append to head of linked list
			lq_data->next = *(context->nl80211);
			*(context->nl80211) = lq_data;
		}
	}

	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl __attribute__ ((unused)) *nla, struct nlmsgerr __attribute__ ((unused)) *err, void *arg) {
	int *finish = arg;

	ASSERT_NOT_NULL(arg);

	*finish = 1;
	return NL_STOP;
}

static int finish_handler(struct nl_msg __attribute__ ((unused)) *msg, void *arg) {
	int *finish = arg;

	ASSERT_NOT_NULL(arg);

	*finish = 1;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg __attribute__ ((unused)) *nla, void *arg) {
	int *finish = arg;

	ASSERT_NOT_NULL(arg);

	*finish = 1;
	return NL_STOP;
}

/**
 * Requests the NL80211 data for a specific interface.
 *
 * @param iface		Interface to get all the NL80211 station information for.
 * @param nl80211	Pointer to linked list with station information. If set to NULL
 *					the pointer will point to a new linked list, if there was any
 *					information retreived.
 */
static void nl80211_link_info_for_interface(struct interface_olsr *iface, struct lq_nl80211_data **nl80211) {
	int finish = 0;
	struct nl_msg *request_message = NULL;
	struct nl_cb *request_cb = NULL;
	struct nl80211_link_info_context link_context = { &finish, nl80211 };

	ASSERT_NOT_NULL(iface);

	if (! iface->is_wireless) {
		// Remove in production code
		olsr_syslog(OLSR_LOG_INFO, "Link entry %s is not a wireless link", iface->int_name);
		return;
	}

	if ((request_message = nlmsg_alloc()) == NULL) {
		olsr_exit("Failed to allocate nl_msg struct", EXIT_FAILURE);
	}

	genlmsg_put(request_message, NL_AUTO_PID, NL_AUTO_SEQ, netlink_id, 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);

	if (nla_put_u32(request_message, NL80211_ATTR_IFINDEX, iface->if_index) == -1) {
		olsr_syslog(OLSR_LOG_ERR, "Failed to add interface index to netlink message");
		exit(1);
	}

#ifdef NL_DEBUG
	if ((request_cb = nl_cb_alloc(NL_CB_DEBUG)) == NULL) {
#else
	if ((request_cb = nl_cb_alloc(NL_CB_DEFAULT)) == NULL) {
#endif
		olsr_exit("Failed to alloc nl_cb struct", EXIT_FAILURE);
	}

	if (nl_cb_set(request_cb, NL_CB_VALID, NL_CB_CUSTOM, parse_nl80211_message, &link_context) != 0) {
		olsr_syslog(OLSR_LOG_ERR, "Failed to set netlink message callback");
		exit(1);
	}

	nl_cb_err(request_cb, NL_CB_CUSTOM, error_handler, &finish);
	nl_cb_set(request_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &finish);
	nl_cb_set(request_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &finish);

	if (nl_send_auto_complete(gen_netlink_socket, request_message) < 0) {
		olsr_syslog(OLSR_LOG_ERR, "Failed sending the request message with netlink");
		exit(1);
	}

	while (! finish) {
		nl_recvmsgs(gen_netlink_socket, request_cb);
	}

	nlmsg_free(request_message);
}

static struct nlattr ** nl80211_parse(struct nl_msg *msg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	static struct nlattr *attr[NL80211_ATTR_MAX + 1];

	nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	          genlmsg_attrlen(gnlh, 0), NULL);

	return attr;
}

static int nl80211_get_noise_cb(struct nl_msg *msg, void *arg)
{
    int8_t *noise = arg;
    struct nlattr **tb = nl80211_parse(msg);
    struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1];

    static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
                  [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
                  [NL80211_SURVEY_INFO_NOISE]     = { .type = NLA_U8  },
    };

    if (!tb[NL80211_ATTR_SURVEY_INFO])
        return NL_SKIP;

    if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
        tb[NL80211_ATTR_SURVEY_INFO], sp))
        return NL_SKIP;

    if (!si[NL80211_SURVEY_INFO_NOISE])
        return NL_SKIP;

    if (!*noise || si[NL80211_SURVEY_INFO_IN_USE])
        *noise = (int8_t)nla_get_u8(si[NL80211_SURVEY_INFO_NOISE]);

    return NL_SKIP;
}

/**
 * Requests the NL80211 data for a specific interface.
 *
 * @param iface		Interface to get all the NL80211 station information for.
 * @param nl80211	Pointer to linked list with station information. If set to NULL
 *					the pointer will point to a new linked list, if there was any
 *					information retreived.
 */
static void nl80211_link_noise_for_interface(struct interface_olsr *iface, int8_t *noise) {
	int finish = 0;
	struct nl_msg *request_message = NULL;
	struct nl_cb *request_cb = NULL;

	ASSERT_NOT_NULL(iface);

	if (! iface->is_wireless) {
		// Remove in production code
		olsr_syslog(OLSR_LOG_INFO, "Link entry %s is not a wireless link", iface->int_name);
		return;
	}

	if ((request_message = nlmsg_alloc()) == NULL) {
		olsr_exit("Failed to allocate nl_msg struct", EXIT_FAILURE);
	}

	genlmsg_put(request_message, NL_AUTO_PID, NL_AUTO_SEQ, netlink_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0);

	if (nla_put_u32(request_message, NL80211_ATTR_IFINDEX, iface->if_index) == -1) {
		olsr_syslog(OLSR_LOG_ERR, "Failed to add interface index to netlink message");
		exit(1);
	}

#ifdef NL_DEBUG
	if ((request_cb = nl_cb_alloc(NL_CB_DEBUG)) == NULL) {
#else
	if ((request_cb = nl_cb_alloc(NL_CB_DEFAULT)) == NULL) {
#endif
		olsr_exit("Failed to alloc nl_cb struct", EXIT_FAILURE);
	}

	if (nl_cb_set(request_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_get_noise_cb, noise) != 0) {
		olsr_syslog(OLSR_LOG_ERR, "Failed to set netlink message callback");
		exit(1);
	}

	nl_cb_err(request_cb, NL_CB_CUSTOM, error_handler, &finish);
	nl_cb_set(request_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &finish);
	nl_cb_set(request_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &finish);

	if (nl_send_auto_complete(gen_netlink_socket, request_message) < 0) {
		olsr_syslog(OLSR_LOG_ERR, "Failed sending the request message with netlink");
		exit(1);
	}

	while (! finish) {
		nl_recvmsgs(gen_netlink_socket, request_cb);
	}

	nlmsg_free(request_message);
}



/**
 * Uses the linux ARP cache to find a MAC address for a neighbor. Does not do
 * actual ARP if it's not found in the cache.
 *
 * @param link		Neighbor to find MAC address of.
 * @param mac		Pointer to buffer of size ETHER_ADDR_LEN that will be
 *					used to write MAC address in (if found).
 * @returns			True if MAC address is found.
 */
static bool mac_of_neighbor(struct link_entry *link, unsigned char *mac) {
	bool success = false;
	struct nl_cache *cache = NULL;
	struct rtnl_neigh *neighbor = NULL;
	struct nl_addr *neighbor_addr_filter = NULL;
	struct nl_addr *neighbor_mac_addr = NULL;
	void *addr = NULL;
	size_t addr_size = 0;

	if (olsr_cnf->ip_version == AF_INET6) {
		addr = &(link->neighbor_iface_addr.v6);
		addr_size = sizeof(struct in6_addr);
	} else {
		addr = &(link->neighbor_iface_addr.v4);
		addr_size = sizeof(struct in_addr);
	}

	if ((neighbor_addr_filter = nl_addr_build(olsr_cnf->ip_version, addr, addr_size)) == NULL) {
		olsr_syslog(OLSR_LOG_ERR, "Failed to build nl_addr struct from link ip address");
		goto cleanup;
	}

#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
	if ((cache = rtnl_neigh_alloc_cache(rt_netlink_socket)) == NULL) {
#else
	if (rtnl_neigh_alloc_cache(rt_netlink_socket, &cache) != 0) {
#endif
		olsr_syslog(OLSR_LOG_ERR, "Failed to allocate netlink neighbor cache");
		goto cleanup;
	}

	if ((neighbor = my_rtnl_neigh_get(cache, link->inter->if_index, neighbor_addr_filter)) == NULL) {
		olsr_syslog(OLSR_LOG_INFO, "Neighbor MAC address not found in ARP cache");
		goto cleanup;
	}

	if ((neighbor_mac_addr = rtnl_neigh_get_lladdr(neighbor)) != NULL) {
		if (nl_addr_get_len(neighbor_mac_addr) != ETHER_ADDR_LEN) {
			olsr_syslog(OLSR_LOG_ERR, "Found a netlink nieghbor but address is not ETHER_ADDR_LEN long");
			goto cleanup;
		}
		memcpy(mac, nl_addr_get_binary_addr(neighbor_mac_addr), ETHER_ADDR_LEN);
		success = true;
	}

cleanup:
	if (cache)
		nl_cache_free(cache);
	if (neighbor)
		rtnl_neigh_put(neighbor);
	if (neighbor_addr_filter)
		nl_addr_put(neighbor_addr_filter);
	// neighbor_mac_filter does not need cleanup

	return success;
}

void nl80211_link_info_init(void) {
	connect_netlink();
}

void nl80211_link_info_cleanup(void) {
	nl_socket_free(gen_netlink_socket);
	nl_socket_free(rt_netlink_socket);
}

static void free_lq_nl80211_data(struct lq_nl80211_data *nl80211) {
	struct lq_nl80211_data *next = nl80211;
	while (nl80211) {
		next = nl80211->next;
		free(nl80211);
		nl80211 = next;	
	}
}

void free_lq_nl80211_vib(struct lq_nl80211_vib *nl80211) {
	struct lq_nl80211_vib *next = nl80211;
	while (nl80211) {
		next = nl80211->next;
		free(nl80211);
		nl80211 = next;	
	}
}


/**
 * Find a object in the linked list that matches the MAC address.
 *
 * @param nl80211_list		Pointer to the linked list to find the object in.
 * @param mac				MAC address to look for, MUST be ETHER_ADDR_LEN long.
 *
 * @returns					Pointer to object or NULL on failure.
 */
static struct lq_nl80211_data *find_lq_nl80211_data_by_mac(struct lq_nl80211_data *nl80211_list, unsigned char *mac) {
	ASSERT_NOT_NULL(nl80211_list);
	ASSERT_NOT_NULL(mac);

	while (nl80211_list) {
		if (memcmp(mac, nl80211_list->mac, ETHER_ADDR_LEN) == 0) {
			return nl80211_list;
		}
		nl80211_list = nl80211_list->next;
	}

	return NULL;
}

static uint8_t bandwidth_to_quality(uint16_t bandwidth) {
	fpm ratio;
	fpm fp_bandwidth;
	fpm penalty;

	if (bandwidth == 0) {
		return 0;
	}

	// BandwidthPenalty = 1 - (Bandwidth / ReferenceBandwidth)

	fp_bandwidth = itofpm(bandwidth);
	fp_bandwidth = fpmidiv(fp_bandwidth, 10); // 100Kbit/sec to Mbit/sec

	ratio = fpmidiv(fp_bandwidth, REFERENCE_BANDWIDTH_MBIT_SEC);
	penalty = fpmsub(itofpm(1), ratio);

	// Convert to 255 based number
	penalty = fpmimul(penalty, 255);

	return fpmtoi(penalty);
}

static uint8_t signal_to_quality(int8_t signal) {
	// Map dBm levels to quality penalties
	struct signal_penalty {
		int8_t signal;
		uint8_t penalty; // 255=1.0
	};
	// Must be ordered
	static struct signal_penalty signal_quality_table[] = {
		{ -75, 30 }, { -80, 255}, { -85, 255 }, { -90, 255}, { -95, 255 }, { -100, 255 }
	};
	static size_t TABLE_SIZE = sizeof(signal_quality_table) / sizeof(struct signal_penalty);

	unsigned int i = 0;
	uint8_t penalty = 0;
	for (i = 0; i < TABLE_SIZE; i++) {
		if (signal <= signal_quality_table[i].signal) {
			penalty = signal_quality_table[i].penalty;
		} else {
			break;
		}
	}

	return penalty;
}

static uint8_t snr_avg_to_quality(int8_t signal,int8_t noise) {
	// Map dBm levels to quality penalties
	int8_t snr = signal - noise;

	struct signal_penalty {
		int8_t signal;
		uint8_t penalty; // 255=1.0
	};

	// Must be ordered
	static struct signal_penalty signal_quality_table[] = {
		{ 20, 120 }, { 15, 200 }, { 10, 240 }, {5, 255}
	};
	static size_t TABLE_SIZE = sizeof(signal_quality_table) / sizeof(struct signal_penalty);

	unsigned int i = 0;
	uint8_t penalty = 0;
	for (i = 0; i < TABLE_SIZE; i++) {
		if (snr <= signal_quality_table[i].signal) {
			penalty = signal_quality_table[i].penalty;
		} else {
			break;
		}
	}

	return penalty;
}

static struct lq_nl80211_vib *find_lq_nl80211_vib_by_mac(struct lq_nl80211_vib **lq_vib_list, struct lq_nl80211_data *lq_data) {
	ASSERT_NOT_NULL(lq_data);
	struct lq_nl80211_vib *tmp_list;
	struct lq_nl80211_vib *lq_vib_data = NULL; 
    
	tmp_list = *lq_vib_list;
	while (tmp_list) {
		if (memcmp(lq_data->mac, tmp_list->mac, ETHER_ADDR_LEN) == 0) {
			//olsr_syslog(OLSR_LOG_ERR,"olsr info compare ok");
			return tmp_list;
		}
		tmp_list = tmp_list->next;
	}

	lq_vib_data = olsr_malloc(sizeof(struct lq_nl80211_vib),"new lq_nl80211_vib struct");
	memcpy(lq_vib_data->mac,lq_data->mac,ETHER_ADDR_LEN);
	lq_vib_data->threshold_sw = false;
	lq_vib_data->next = NULL;
	lq_vib_data->cur_snr = 0;
	lq_vib_data->hop_flag = 0; 
    
	if(*lq_vib_list == NULL){
		*lq_vib_list = lq_vib_data;
	}else{
		lq_vib_data->next = *lq_vib_list;
		*lq_vib_list = lq_vib_data;
	}

	return lq_vib_data;
}

struct lq_nl80211_vib *lq_vib_list=NULL;
#define THRESHOLD_VIB 10

static uint8_t snr_to_quality(struct lq_nl80211_data *lq_data, int8_t signal,int8_t noise) {
	int8_t snr = signal - noise;
	struct lq_nl80211_vib *lq_vib_data=NULL;
	
	// Map dBm levels to quality penalties
	struct signal_penalty {
		int8_t signal;
		uint8_t penalty; // 255=1.0
	};
	// Must be ordered
	static struct signal_penalty signal_quality_table[] = {
		{ 20, 120 }, { 15, 200 }, { 10, 240 }, {5, 255}
	};
	static size_t TABLE_SIZE = sizeof(signal_quality_table) / sizeof(struct signal_penalty);

	olsr_syslog(OLSR_LOG_ERR,"olsrd snr = %d\r\n",snr);
	unsigned int i = 0;
	uint8_t penalty = 0;

	lq_vib_data = find_lq_nl80211_vib_by_mac(&lq_vib_list,lq_data);

	if(lq_vib_data->cur_snr == 0){
            lq_vib_data->cur_snr = snr;	
	}else{
            if((snr >= lq_vib_data->cur_snr + 20) || (snr >= lq_vib_data->cur_snr - 20)){
	        lq_vib_data->hop_flag++;
		if(lq_vib_data->hop_flag >= 3){
	            lq_vib_data->cur_snr=snr;	
		    lq_vib_data->hop_flag = 0;
		}else{
	            snr=lq_vib_data->cur_snr;	
		}
	    }else{
	        if(lq_vib_data->hop_flag > 0){
	            lq_vib_data->hop_flag=0;	
		}
		lq_vib_data->cur_snr = snr;
	    }	
	}

	if(snr >= (signal_quality_table[0].signal + THRESHOLD_VIB)){
		//olsr_syslog(OLSR_LOG_ERR,"olsrd snr debug 1\r\n");
		lq_vib_data->threshold_sw = false;

		return penalty;
	}

	if(((signal_quality_table[0].signal) < snr) && (snr < (signal_quality_table[0].signal + THRESHOLD_VIB))){
		if(lq_vib_data->threshold_sw){
		        //olsr_syslog(OLSR_LOG_ERR,"olsrd snr debug 2\r\n");
			return signal_quality_table[0].penalty;
		}else{
			//olsr_syslog(OLSR_LOG_ERR,"olsrd snr debug 3\r\n");
			return penalty;
		}
	}

	for (i = 0; i < TABLE_SIZE; i++) {
        	if (snr <= signal_quality_table[i].signal) {
			penalty = signal_quality_table[i].penalty;
			lq_vib_data->threshold_sw = true;
		} else {
			break;
		}
	}

	return penalty;
}

void nl80211_link_info_get(void) {
	struct interface_olsr *next_interface = NULL;
	struct lq_nl80211_data *nl80211_list = NULL;
	struct link_entry *link = NULL;
	struct lq_nl80211_data *lq_data = NULL;
	struct lq_ffeth_hello *lq_ffeth = NULL;
	unsigned char mac_address[ETHER_ADDR_LEN];

	uint8_t penalty_bandwidth;
	uint8_t penalty_signal;

	int8_t noise = 0;

	nl80211_link_noise_for_interface(ifnet,&noise);
	//olsr_syslog(OLSR_LOG_ERR,"olsrd noise = %d\r\n",noise);

	// Get latest 802.11 status information for all interfaces
	// This list will contain OLSR and non-OLSR nodes
	for (next_interface = ifnet; next_interface; next_interface = next_interface->int_next) {
		nl80211_link_info_for_interface(next_interface, &nl80211_list);
	}

	if (nl80211_list == NULL) {
		olsr_syslog(OLSR_LOG_INFO, "Failed to retreive any NL80211 data");
		return;
	}

	OLSR_FOR_ALL_LINK_ENTRIES(link) {
		lq_ffeth = (struct lq_ffeth_hello *) link->linkquality;
		lq_ffeth->lq.valueBandwidth = 0;
		lq_ffeth->lq.valueRSSI = 0;
		lq_ffeth->smoothed_lq.valueBandwidth = 0;
		lq_ffeth->smoothed_lq.valueRSSI = 0;

		if (mac_of_neighbor(link, mac_address)) {
			if ((lq_data = find_lq_nl80211_data_by_mac(nl80211_list, mac_address)) != NULL) {
				penalty_bandwidth = bandwidth_to_quality(lq_data->bandwidth);
				//penalty_signal = signal_to_quality(lq_data->signal);
				//penalty_signal = snr_to_quality(lq_data,lq_data->signal,noise);
				penalty_signal = snr_avg_to_quality(lq_data->signal_avg, noise);

				lq_ffeth->lq.valueBandwidth = penalty_bandwidth;
				lq_ffeth->lq.valueRSSI = penalty_signal;
				lq_ffeth->smoothed_lq.valueBandwidth = penalty_bandwidth;
				lq_ffeth->smoothed_lq.valueRSSI = penalty_signal;

				olsr_syslog(OLSR_LOG_INFO, "Apply 802.11: iface(%s) neighbor(%s) bandwidth(%dMb = %d) rssi(%ddBm = %d) rssi_avg(%ddbm)",
						link->if_name, ether_ntoa((struct ether_addr *)mac_address),
						lq_data->bandwidth / 10, penalty_bandwidth, lq_data->signal, penalty_signal, lq_data->signal_avg);
			} else
				olsr_syslog(OLSR_LOG_INFO, "NO match ;-(!");
		}
	} OLSR_FOR_ALL_LINK_ENTRIES_END(link)

	free_lq_nl80211_data(nl80211_list);
}

#endif /* LINUX_NL80211 */
#endif /* __linux__ */
