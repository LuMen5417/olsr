
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas Tonnesen(andreto@olsr.org)
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

/*
 * Dynamic linked library for the olsr.org olsr daemon
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "olsrd_plugin.h"
#include "olsrd_jsoninfo.h"
#include "defs.h"

#define PLUGIN_NAME    "JSON info and dyn_gw plugin"
#define PLUGIN_VERSION "0.0"
#define PLUGIN_AUTHOR   "Hans-Christoph Steiner"
#define MOD_DESC PLUGIN_NAME " " PLUGIN_VERSION " by " PLUGIN_AUTHOR
#define PLUGIN_INTERFACE_VERSION 5

union olsr_ip_addr jsoninfo_accept_ip;
union olsr_ip_addr jsoninfo_listen_ip;
int ipc_port;
int nompr;
bool http_headers;
int jsoninfo_ipv6_only;

static void my_init(void) __attribute__ ((constructor));
static void my_fini(void) __attribute__ ((destructor));

/**
 *Constructor
 */
static void
my_init(void)
{
  /* Print plugin info to stdout */
  printf("%s\n", MOD_DESC);

  /* defaults for parameters */
  ipc_port = 9090;
  http_headers = false;
  jsoninfo_ipv6_only = false;

  if (olsr_cnf->ip_version == AF_INET) {
    jsoninfo_accept_ip.v4.s_addr = htonl(INADDR_LOOPBACK);
    jsoninfo_listen_ip.v4.s_addr = htonl(INADDR_ANY);
  } else {
    jsoninfo_accept_ip.v6 = in6addr_loopback;
    jsoninfo_listen_ip.v6 = in6addr_any;
  }

  /* highlite neighbours by default */
  nompr = 0;
}

/**
 *Destructor
 */
static void
my_fini(void)
{
  /* Calls the destruction function
   * olsr_plugin_exit()
   * This function should be present in your
   * sourcefile and all data destruction
   * should happen there - NOT HERE!
   */
  olsr_plugin_exit();
}

int
olsrd_plugin_interface_version(void)
{
  return PLUGIN_INTERFACE_VERSION;
}

static int
store_string(const char *value, void *data, set_plugin_parameter_addon addon __attribute__ ((unused)))
{
  char *str = data;
  snprintf(str, FILENAME_MAX, "%s", value);
  return 0;
}

static int
store_boolean(const char *value, void *data, set_plugin_parameter_addon addon __attribute__ ((unused)))
{
  bool *dest = data;
  if(strcmp(value, "yes") == 0)
    *dest = true;
  else if (strcmp(value, "no") == 0)
    *dest = false;
  else
    return 1; //error

  return 0;
}

static const struct olsrd_plugin_parameters plugin_parameters[] = {
  {.name = "port",.set_plugin_parameter = &set_plugin_port,.data = &ipc_port},
  {.name = "accept",.set_plugin_parameter = &set_plugin_ipaddress,.data = &jsoninfo_accept_ip},
  {.name = "listen",.set_plugin_parameter = &set_plugin_ipaddress,.data = &jsoninfo_listen_ip},
  {.name = "uuidfile",.set_plugin_parameter = &store_string,.data = uuidfile},
  {.name = "httpheaders",.set_plugin_parameter = &store_boolean,.data = &http_headers},
  {.name = "ipv6only", .set_plugin_parameter = &set_plugin_boolean, .data = &jsoninfo_ipv6_only},
};

void
olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params, int *size)
{
  *params = plugin_parameters;
  *size = sizeof(plugin_parameters) / sizeof(*plugin_parameters);
}

/*
 * Local Variables:
 * mode: c
 * style: linux
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
