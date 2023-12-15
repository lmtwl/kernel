#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_ether.h> // 包含 Ethernet 头部定义

static struct nf_hook_ops *nfho = NULL;

struct network_info
{
  uint32_t net_ip;
  uint32_t net_mask;
  const char *net_name;
};
static struct network_info networks[] = {
    {htonl(0x01010000), htonl(0xFFFFFE00), "1.1.0.0/23"},
    {htonl(0x02020200), htonl(0xFFFFFF00), "2.2.2.0/24"}};

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct udphdr *udph;
  struct ethhdr *eth_header;
  int i;
  if (!skb)
  {
    printk(KERN_INFO "Received NULL skb\n");
    return NF_ACCEPT;
  }

  if (!pskb_may_pull(skb, sizeof(struct iphdr)))
  {
    printk(KERN_INFO "Failed to pull IP header from skb\n");
    return NF_ACCEPT;
  }
  eth_header = eth_hdr(skb);
  iph = ip_hdr(skb);

  if (iph->protocol != IPPROTO_UDP)
  {
    // printk(KERN_INFO "Not a UDP packet\n");
    return NF_ACCEPT;
  }

  if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
  {
    printk(KERN_INFO "Failed to pull UDP header from skb\n");
    return NF_ACCEPT;
  }

  udph = udp_hdr(skb);
  // printk(KERN_INFO " codspeedy %pI4: %d   %pI4: %d\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));

  for (i = 0; i < ARRAY_SIZE(networks); ++i)
  {
    if ((networks[i].net_ip & networks[i].net_mask) == (iph->daddr & networks[i].net_mask))
    {
      printk(KERN_INFO "Dropping packet from %s %pI4 -> %pI4\n", networks[i].net_name, &iph->saddr, &iph->daddr);
      return NF_DROP;
    }
  }
  return NF_ACCEPT;
}
static int __init pcap_init(void)
{
  nfho = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

  nfho->hook = (nf_hookfn *)hook_func;
  nfho->hooknum = NF_INET_PRE_ROUTING;
  nfho->pf = PF_INET;
  nfho->priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, nfho);
  return 0;
}

static void __exit pcap_exit(void)
{
  nf_unregister_net_hook(&init_net, nfho);
  kfree(nfho);
}

module_init(pcap_init);
module_exit(pcap_exit);