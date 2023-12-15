#include <stdio.h>
#include <string.h>

int main() {
    unsigned char buf[27]={1};
    // memset(buf, 0, sizeof(buf));
    buf[0] = 0x31;
    // 假设 first_byte2 和 first_byte4 已经定义并赋值
    buf[1] = 0x11;
    buf[2] = 0x00;
    buf[3] = 0x22;
    buf[12] = 0x15;

    // 使用 memset 设置整个数组
    

    // 打印缓冲区内容
    for (size_t i = 0; i < sizeof(buf); ++i) {
        printf("buf[%zu]: 0x%x\n", i, buf[i]);
    }

    return 0;
}
