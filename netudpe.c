#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
// 目标IP地址和端口号
#define DEST_IP "172.18.1.89"
#define DEST_PORT 12345

// 发送UDP数据包的函数
static int send_udp_packet(struct net_device *dev)
{
    struct sk_buff *skb;
    struct udphdr *udp_header;
    struct iphdr *ip_header;
    struct sockaddr_in dest_addr;

    // 为数据包分配内存
    skb = alloc_skb(sizeof(struct iphdr) + sizeof(struct udphdr) + 10, GFP_ATOMIC);
    if (!skb)
    {
        return -ENOMEM;
    }

    // 设置目标地址信息
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = in_aton(DEST_IP);
    dest_addr.sin_port = htons(DEST_PORT);

    // 设置IP头部
    ip_header = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(skb->len);
    ip_header->id = htons(1234);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->saddr = 0; // Set the source IP address to 0. The kernel will fill it.
    ip_header->daddr = dest_addr.sin_addr.s_addr;

    // 设置UDP头部
    udp_header = (struct udphdr *)skb_put(skb, sizeof(struct udphdr));
    udp_header->source = htons(5678); // Source port (you can choose any available port)
    udp_header->dest = dest_addr.sin_port;
    udp_header->len = htons(skb->len - sizeof(struct iphdr));
    udp_header->check = 0; // UDP checksum is optional

    // 使用dev_queue_xmit将数据包发送出去
    dev_queue_xmit(skb);

    return 0;
}

static int __init my_module_init(void)
{
    struct net_device *dev;

    // 获取默认网络设备（这里假设是eth0）
    dev = dev_get_by_name(&init_net, "eth0");
    if (!dev)
    {
        pr_err("Failed to get network device\n");
        return -ENODEV;
    }

    // 发送UDP数据包
    send_udp_packet(dev);

    // 释放网络设备引用
    dev_put(dev, 1);

    return 0;
}

static void __exit my_module_exit(void)
{
    pr_info("Module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
