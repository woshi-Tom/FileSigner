# Makefile for FileSigner
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I./src/include
LDFLAGS = -lssl -lcrypto
DEBUG_FLAGS = -g -O0
RELEASE_FLAGS = -O2 -DNDEBUG

# 检查操作系统
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    CFLAGS += -D_POSIX_C_SOURCE=200809L
    LDFLAGS += -pthread
endif
ifeq ($(UNAME_S),Darwin)
    CFLAGS += -I/usr/local/opt/openssl/include
    LDFLAGS += -L/usr/local/opt/openssl/lib
endif

# 源文件
SRC_DIR = src
MAIN_SRC = $(SRC_DIR)/main/file_signer.c
VERIFY_SRC = $(SRC_DIR)/main/verify_sig.c
UTILS_SRC = $(SRC_DIR)/utils/file_utils.c $(SRC_DIR)/utils/crypto_utils.c

# 目标文件
MAIN_OBJ = build/obj/file_signer.o
VERIFY_OBJ = build/obj/verify_sig.o
UTILS_OBJ = build/obj/file_utils.o build/obj/crypto_utils.o

# 可执行文件
TARGET_MAIN = build/bin/file_signer
TARGET_VERIFY = build/bin/verify_sig

# 默认目标
all: release

# 调试版本
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET_MAIN) $(TARGET_VERIFY)

# 发布版本
release: CFLAGS += $(RELEASE_FLAGS)
release: $(TARGET_MAIN) $(TARGET_VERIFY)

# 主程序
$(TARGET_MAIN): $(MAIN_OBJ) $(UTILS_OBJ)
	@mkdir -p build/bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 验证工具
$(TARGET_VERIFY): $(VERIFY_OBJ) $(UTILS_OBJ)
	@mkdir -p build/bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译对象文件
build/obj/%.o: $(SRC_DIR)/main/%.c
	@mkdir -p build/obj
	$(CC) $(CFLAGS) -c $< -o $@

build/obj/%.o: $(SRC_DIR)/utils/%.c
	@mkdir -p build/obj
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -rf build/obj/*.o
	rm -rf build/bin/*

distclean: clean
	rm -rf build/

# 安装到系统
install: release
	@mkdir -p /usr/local/bin
	cp $(TARGET_MAIN) /usr/local/bin/
	cp $(TARGET_VERIFY) /usr/local/bin/
	chmod +x /usr/local/bin/file_signer
	chmod +x /usr/local/bin/verify_sig

# 卸载
uninstall:
	rm -f /usr/local/bin/file_signer
	rm -f /usr/local/bin/verify_sig

# 测试
test: debug
	@echo "Running tests..."
	@cd test && ./run_tests.sh

# 静态链接版本（实验性）
static: CFLAGS += -static
static: LDFLAGS += -static
static: clean $(TARGET_MAIN) $(TARGET_VERIFY)

# 帮助
help:
	@echo "可用目标:"
	@echo "  all/release  - 编译发布版本 (默认)"
	@echo "  debug        - 编译调试版本"
	@echo "  clean        - 清理对象文件"
	@echo "  distclean    - 完全清理"
	@echo "  install      - 安装到系统"
	@echo "  uninstall    - 卸载"
	@echo "  test         - 运行测试"
	@echo "  static       - 静态链接版本"
	@echo "  help         - 显示此帮助"

.PHONY: all debug release clean distclean install uninstall test static help