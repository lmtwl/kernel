#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

char *is_valid_cidr(const char *cidr)
{
    char ip_address[16];           // 存储 IP 地址的字符串
    char subnet_mask_str[3];       // 存储子网掩码长度的字符串
    unsigned int subnet_mask_bits; // 存储子网掩码长度的整数值

    // 解析输入的 CIDR 格式
    if (sscanf(cidr, "%15[0-9.]/%2s", ip_address, subnet_mask_str) != 2)
    {
        return NULL;
    }

    // 解析子网掩码长度的整数值
    subnet_mask_bits = atoi(subnet_mask_str);
    if (subnet_mask_bits < 0 || subnet_mask_bits > 32)
    {
        return NULL;
    }

    // 将 IP 地址转换为二进制形式
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_address, &addr) != 1)
    {
        return NULL;
    }
    unsigned int ip_binary = ntohl(addr.s_addr);

    // 将 IPv4 地址向右移动（32 - 子网掩码长度），再向左移动相同的位数
    unsigned int mask = 0xFFFFFFFF << (32 - subnet_mask_bits);
    unsigned int network_address = (ip_binary >> (32 - subnet_mask_bits)) << (32 - subnet_mask_bits);

    // 格式化为 CIDR 形式
    char *result = (char *)malloc(20); // 预留足够的空间来存储 CIDR 字符串
    snprintf(result, 20, "%u.%u.%u.%u/%u", (network_address >> 24) & 0xFF, (network_address >> 16) & 0xFF,
             (network_address >> 8) & 0xFF, network_address & 0xFF, subnet_mask_bits);

    return result;
}

char *ipv4_subnet_to_hex(const char *ip_address_with_mask)
{
    char *ip_address = strdup(ip_address_with_mask); // 复制一份地址以保持原始数据不变
    char *subnet_mask_str = strchr(ip_address, '/'); // 查找子网掩码分隔符
    if (subnet_mask_str == NULL)
    {
        fprintf(stderr, "Error: Invalid IPv4 address with mask\n");
        free(ip_address);
        return NULL;
    }

    // 将子网掩码分隔符替换为字符串结束符
    *subnet_mask_str = '\0';
    subnet_mask_str++; // 子网掩码字符串的起始位置

    // 将 IPv4 地址转换为十六进制
    unsigned int ip_a, ip_b, ip_c, ip_d;
    sscanf(ip_address, "%u.%u.%u.%u", &ip_a, &ip_b, &ip_c, &ip_d);
    char ip_hex[11]; // IPv4 地址最多需要 10 个字符加上结尾的 '\0'
    snprintf(ip_hex, sizeof(ip_hex), "0x%02X%02X%02X%02X", ip_a, ip_b, ip_c, ip_d);

    // 将子网掩码转换为十六进制
    int subnet_mask_bits = atoi(subnet_mask_str);
    if (subnet_mask_bits < 0 || subnet_mask_bits > 32)
    {
        fprintf(stderr, "Error: Invalid subnet mask\n");
        free(ip_address);
        return NULL;
    }
    unsigned int subnet_mask_int = 0xFFFFFFFF << (32 - subnet_mask_bits);
    char subnet_hex[11]; // 子网掩码最多需要 10 个字符加上结尾的 '\0'
    snprintf(subnet_hex, sizeof(subnet_hex), "0x%X", subnet_mask_int);

    // 返回结果
    char *result = (char *)malloc(strlen(ip_hex) + strlen(subnet_hex) + 2); // 预留一个空格和一个 '\0'
    snprintf(result, strlen(ip_hex) + strlen(subnet_hex) + 2, "%s %s", ip_hex, subnet_hex);

    free(ip_address); // 释放内存
    return result;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <IPv4_address/mask>\n", argv[0]);
        return 1;
    }

    char *network_address = is_valid_cidr(argv[1]);
    if (network_address == NULL)
    {
        fprintf(stderr, "Error: Invalid CIDR format\n");
        return 1;
    }
    else
    {
        char *result = ipv4_subnet_to_hex(network_address);
        if (result != NULL)
        {
            printf("IPv4 %s地址的十六进制表示为: %s\n", network_address,result);
            free(result); // 释放内存
        }
    }
    free(network_address); // 释放内存
    return 0;
}
