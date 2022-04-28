#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/version.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>

static struct iphdr *ip_header;
static struct tcphdr *tcp_header;
static struct udphdr *udp_header;

unsigned int sport,
    dport;

const char *nf_inet_hooks_ptr[] = {
    "PRE_ROUTING",
    "LOCAL_IN",
    "FORWARD",
    "LOCAL_OUT",
    "POST_ROUTING",
    "NUMHOOKS"};

static unsigned int hookfn(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
  // char sip[16], dip[16];
  struct ethhdr *eth;
  if (!skb)
  {
    return NF_ACCEPT;
  }

  eth = (struct ethhdr *)skb_mac_header(skb);
  skb_linearize(skb);

  ip_header = ip_hdr(skb);

  if (ip_header->protocol == IPPROTO_TCP)
  {
    tcp_header = tcp_hdr(skb);
    sport = htons((unsigned short int)tcp_header->source);
    dport = htons((unsigned short int)tcp_header->dest);
    if (sport == 80 || dport == 80)
      pr_info("hookfn: hook is tcp %s:%s-%s %pI4:%d--%pI4:%d\n", nf_inet_hooks_ptr[state->hook], state->in->name, state->out->name, &ip_header->saddr, sport, &ip_header->daddr, dport);
  }
  if (ip_header->protocol == IPPROTO_UDP)
  {
    udp_header = udp_hdr(skb);
    sport = htons((unsigned short int)udp_header->source);
    dport = htons((unsigned short int)udp_header->dest);
    // pr_info("hookfn: hook is udp %s:%s-%s %pI4:%d--%pI4:%d\n", nf_inet_hooks_ptr[state->hook], state->in->name, state->out->name, &ip_header->saddr, sport, &ip_header->daddr, dport);
  }
  // snprintf(sip, 16, "%pI4", &ip_header->saddr);
  // snprintf(dip, 16, "%pI4", &ip_header->daddr);
  // if (sport != 22 && dport !=22 )
  // pr_info("hookfn: hook is %d:%s-- %s--%s --%s:%d--%s:%d\n", state->hook, nf_inet_hooks_ptr[state->hook], state->in->name, state->out->name, sip, sport, dip, dport);

  return NF_ACCEPT;
}

static struct nf_hook_ops nf_hook_ops[] __read_mostly = {
    {
        .hook = hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_LAST,
    },
    {
        .hook = hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_FORWARD,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_MANGLE,
    },
    {
        .hook = hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_LAST,
    },
};

int nf_prtip_init(void)
{
  int err = 0;
  err = nf_register_net_hook(&init_net, &nf_hook_ops[0]);
  err = nf_register_net_hook(&init_net, &nf_hook_ops[1]);
  err = nf_register_net_hook(&init_net, &nf_hook_ops[2]);
  err = nf_register_net_hook(&init_net, &nf_hook_ops[3]);
  err = nf_register_net_hook(&init_net, &nf_hook_ops[4]);
  if (err < 0)
  {
    pr_notice("nf_ip_df_init: can't register hooks.\n");
  }
  pr_emerg("INT_MIN = %d\n", INT_MIN);
  pr_info("ip_mtu: register hooks success.\n");
  return err;
}

void nf_prtip_fini(void)
{
  nf_unregister_net_hook(&init_net, &nf_hook_ops[0]);
  nf_unregister_net_hook(&init_net, &nf_hook_ops[1]);
  nf_unregister_net_hook(&init_net, &nf_hook_ops[2]);
  nf_unregister_net_hook(&init_net, &nf_hook_ops[3]);
  nf_unregister_net_hook(&init_net, &nf_hook_ops[4]);
}

module_init(nf_prtip_init);
module_exit(nf_prtip_fini);
MODULE_LICENSE("GPL");
