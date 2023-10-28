// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>

#include "aes.h"
#include "aes_whitebox.h"
#include "utils.h"


static void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}

static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != size << 1) {
    err_quit("Invalid param %s (got %d, expected %d)",
        param_name, strlen(in), size << 1);
  }
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}

void syntax(const char* program_name) {
  err_quit("usage: %s <cfb|ofb|ctr>"
      " <要加密的十六进制字符串>"
      " <IV>", program_name);
}

uint64_t get_cur_time_ms() {
  // 获得当前时间us为单位
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}
uint64_t get_cur_time_us() {
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

#define getTime get_cur_time_us

au_main

{
  void (*encrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c) = NULL;
  void (*decrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c) = NULL;

  if (argc != 4) {
    syntax(argv[0]);
  } else if (strcmp(argv[1], "cfb") == 0) {
    encrypt = &aes_whitebox_encrypt_cfb;
    decrypt = &aes_whitebox_decrypt_cfb;
  } else if (strcmp(argv[1], "ofb") == 0) {
    encrypt = &aes_whitebox_encrypt_ofb;
    decrypt = &aes_whitebox_decrypt_ofb;
  } else if (strcmp(argv[1], "ctr") == 0) {
    encrypt = &aes_whitebox_encrypt_ctr;
    decrypt = &aes_whitebox_decrypt_ctr;
  } else {
    syntax(argv[0]);
  }

  size_t inputLen = strlen(argv[2]);
  if (inputLen > 0 && inputLen % 2 != 0) {
    err_quit("输入要加密的十六进制字符串的个数必须是偶数，当前输入的字符个数是：%d", inputLen);
  }

  if (strlen(argv[3]) % 32 != 0) {
      err_quit("输入的IV必须是16个十六进制数据");
  }

  int inputByte = inputLen / 2;
  uint8_t plain[inputByte], iv_or_nonce[16], output[inputByte];

  read_hex(argv[2], plain, inputByte, "plain");
  read_hex(argv[3], iv_or_nonce, 16, "iv-or-nonce");
  
  printf("--> 输入的十六进制字符串长度：%d 十六进制个数 %d\n", inputLen, inputByte);
  printf("--> 开始%s加密:\n", argv[1]);
  for(int index = 0; index < inputByte; index++)
    printf("%.2x", plain[index]);
  printf("\n");
  uint64_t timeStart = getTime();
  printf("--> 中间值 start %lldus", timeStart);
  (*encrypt)(iv_or_nonce, plain, inputByte, output);
  uint64_t timeEnd = getTime();
  printf("\n--> 中间值 end %lldus cost %lldus", timeEnd , timeEnd - timeStart);
  printf("\n--> 加密后的密文：\n");
  for(int index = 0; index < inputByte; index++)
      printf("%.2x", output[index]);
  printf("\n\n\n");

  printf("--> 开始%s解密：\n", argv[1]);
  for(int index = 0; index < inputByte; index++)
      printf("%.2x", output[index]);
  printf("\n");
  timeStart = getTime();
  printf("--> 中间值 start %lld", timeStart);
  (*decrypt)(iv_or_nonce, output, inputByte, plain);
  timeEnd = getTime();
  printf("\n--> 中间值 end %lldus cost %lldus", timeEnd , timeEnd - timeStart);

  printf("\n--> 解密后的明文：\n");
  for(int index = 0; index < inputByte; index++)
      printf("%.2x", plain[index]);
  printf("\n\n\n");
}

au_endmain
