//
//  Kiwisec
//
#ifndef KIWISEC_WHITEBOX_UTILS_H
#define KIWISEC_WHITEBOX_UTILS_H

#include <stdio.h>

void pkcs7_padding(unsigned char *buf, int len,
                   unsigned char **pad_buf, int *pad_size);

void pkcs7_unpadding(unsigned char *buf, int len,int *pad_size);

#endif //KIWISEC_WHITEBOX_UTILS_H