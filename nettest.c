#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho = NULL;
static int sendudp(char *eth, u_char *smac, u_char *dmac, u_char *pkt, int pkt_len, __be32 src_ip, __be32 dst_ip, uint16_t src_port, uint16_t dst_port);

struct network_info
{
  uint32_t net_ip;
  uint32_t net_mask;
  const char *net_name;
};
static struct network_info networks[] = {
    {htonl(0x2D4DF000), htonl(0xFFFFC000), "45.77.240.0/14"},
    {htonl(0x2D4C9000), htonl(0xFFFFF800), "45.76.144.0/21"},
    {htonl(0xD5B34000), htonl(0xFFFF8000), "213.179.192.0/19"},
    {htonl(0xCBC37800), htonl(0xFFFFFC00), "203.195.120.0/22"},
    {htonl(0xAE7F4400), htonl(0xFFFFFE00), "174.127.68.0/23"},
    {htonl(0x8BB48000), htonl(0xFFFF8000), "139.180.128.0/19"}};

static int sendudp(char *eth, u_char *smac, u_char *dmac, u_char *pkt, int pkt_len, __be32 src_ip, __be32 dst_ip, uint16_t src_port, uint16_t dst_port)
{

  int ret = -1;
  unsigned int pktSize;
  struct sk_buff *skb = NULL;
  struct net_device *dev = NULL;
  struct ethhdr *ethheader = NULL;
  struct iphdr *ipheader = NULL;
  struct udphdr *udpheader = NULL;
  u_char *pdata = NULL;

  printk("sport:%d dport %d \n", src_port, dst_port);
  /*参数合法性检查*/
  if (NULL == smac || NULL == dmac)
    goto out;

  /*通过出口接口名称获取接口设备信息*/
  dev = dev_get_by_name(&init_net, eth);
  if (NULL == dev)
  {
    printk(KERN_ERR "unknow device name:%s\n", eth);
    goto out;
  }

  /*计算报文长度*/
  pktSize = pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr) + LL_RESERVED_SPACE(dev);
  skb = alloc_skb(pktSize, GFP_ATOMIC);
  if (NULL == skb)
  {
    printk(KERN_ERR "malloc skb fail\n");
    goto out;
  }

  /*在头部预留需要的空间*/
  skb_reserve(skb, pktSize);

  skb->dev = dev;
  skb->pkt_type = PACKET_OTHERHOST;
  skb->protocol = __constant_htons(ETH_P_IP);
  skb->ip_summed = CHECKSUM_NONE; // udp校验和初始化
  skb->priority = 0;

  pdata = skb_push(skb, pkt_len);
  if (NULL != pkt)
    memcpy(pdata, pkt, pkt_len);

  /*填充udp头部*/
  udpheader = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
  memset(udpheader, 0, sizeof(struct udphdr));
  udpheader->source = htons(src_port);
  udpheader->dest = htons(dst_port);
  skb->csum = 0;
  udpheader->len = htons(sizeof(struct udphdr) + pkt_len);
  udpheader->check = 0;
  skb_reset_transport_header(skb);

  /*填充IP头*/
  ipheader = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
  ipheader->version = 4;
  ipheader->ihl = sizeof(struct iphdr) >> 2; // ip头部长度
  ipheader->frag_off = 0;
  ipheader->protocol = IPPROTO_UDP;
  ipheader->tos = 0;
  ipheader->saddr = src_ip;
  ipheader->daddr = dst_ip;
  ipheader->ttl = 0x40;
  ipheader->tot_len = htons(pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr));
  ipheader->check = 0;
  ipheader->check = ip_fast_csum((unsigned char *)ipheader, ipheader->ihl);
  skb_reset_network_header(skb);

  skb->csum = skb_checksum(skb, ipheader->ihl * 4, skb->len - ipheader->ihl * 4, 0);
  udpheader->check = csum_tcpudp_magic(src_ip, dst_ip, skb->len - ipheader->ihl * 4, IPPROTO_UDP, skb->csum);

  /*填充MAC*/
  ethheader = (struct ethhdr *)skb_push(skb, 14);
  memcpy(ethheader->h_dest, dmac, ETH_ALEN);
  memcpy(ethheader->h_source, smac, ETH_ALEN);
  ethheader->h_proto = __constant_htons(ETH_P_IP);
  skb_reset_mac_header(skb);

  /*send pkt
      dev_queue_xmit发送之后会释放相应的空间。
      因此注意不能做重复释放
  */
  if (0 > dev_queue_xmit(skb))
  {
    printk(KERN_ERR "send pkt error");
    goto out;
  }
  ret = 0;

  printk(KERN_INFO "send success\n");
out:
  if (ret != 0 && NULL != skb)
  {
    dev_put(dev);
    kfree_skb(skb);
  }
  return NF_ACCEPT;
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct udphdr *udph;
  struct ethhdr *eth_header;
  int i;
  unsigned int payload_len;
  unsigned char first_byte1;
  unsigned char first_byte2;
  unsigned char first_byte3;
  unsigned char first_byte4;
  unsigned char first_byte5;
  unsigned char first_byte6;
  unsigned char first_byte10;
  unsigned char first_byte11;

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
  payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct udphdr);
  first_byte1 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr)));
  if (payload_len == 18)
  {
    if (first_byte1 == 0x28)
    {
      printk(KERN_INFO " codspeedy1 %pI4: %d   %pI4 : %d\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
      for (i = 0; i < ARRAY_SIZE(networks); ++i)
      {
        if ((networks[i].net_ip & networks[i].net_mask) == (iph->daddr & networks[i].net_mask))
        {
          unsigned char buf[27] = {0};
          buf[0] = 0x29;
          buf[13] = 0x01;

          first_byte2 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 1));
          first_byte3 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 2));
          first_byte4 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 3));
          first_byte5 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 4));
          first_byte6 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 5));
          first_byte10 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 9));
          first_byte11 = *((unsigned char *)(skb->data + iph->ihl * 4 + sizeof(struct udphdr) + 10));
          buf[1] = first_byte10;
          buf[2] = first_byte11;
          buf[5] = first_byte2;
          buf[6] = first_byte3;
          buf[7] = first_byte4;
          buf[8] = first_byte5;
          buf[9] = first_byte6;
          printk(KERN_INFO " codspeedysend %pI4: %d   %pI4 : %d\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
          sendudp(state->in->name, eth_header->h_dest, eth_header->h_source, buf, 27, iph->daddr, iph->saddr, ntohs(udph->dest), ntohs(udph->source));
          return NF_DROP;
        }
      }
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
MODULE_LICENSE("GPL");
MODULE_AUTHOR("LiMing");
MODULE_DESCRIPTION("Netfilter Module");
