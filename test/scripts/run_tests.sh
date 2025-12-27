#!/bin/bash
# 运行测试脚本

set -e

echo "=== FileSigner 测试套件 ==="
echo

# 创建测试目录
TEST_DIR="test/test_files"
CERT_DIR="test/certificates"
mkdir -p "$TEST_DIR"
mkdir -p "$CERT_DIR"

# 生成测试证书（如果不存在）
if [ ! -f "$CERT_DIR/ca_cert.pem" ] || [ ! -f "$CERT_DIR/ca_key.pem" ]; then
    echo "生成测试证书..."
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/ca_key.pem" \
        -out "$CERT_DIR/ca_cert.pem" -days 365 -nodes \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=Test/OU=Test/CN=Test CA"
fi

# 创建测试文件
echo "创建测试文件..."
for i in {1..5}; do
    echo "这是测试文件 $i 的内容" > "$TEST_DIR/document$i.txt"
    echo "PDF 文件 $i 的模拟内容" > "$TEST_DIR/document$i.pdf"
done

# 编译测试程序
echo "编译程序..."
cd ../..
make debug

# 测试1: 批量签名
echo
echo "=== 测试1: 批量签名 ==="
./build/bin/file_signer -c "$CERT_DIR/ca_cert.pem" \
    -k "$CERT_DIR/ca_key.pem" \
    -i "$TEST_DIR" \
    -v

# 检查签名文件
echo
echo "检查签名文件..."
SIG_COUNT=$(find "$TEST_DIR" -name "*.sig" | wc -l)
echo "找到 $SIG_COUNT 个签名文件"

if [ $SIG_COUNT -eq 10 ]; then
    echo "✓ 批量签名测试通过"
else
    echo "✗ 批量签名测试失败"
    exit 1
fi

# 测试2: 验证签名
echo
echo "=== 测试2: 验证签名 ==="
for sig_file in "$TEST_DIR"/*.sig; do
    original_file="${sig_file%.sig}"
    ./build/bin/verify_sig "$CERT_DIR/ca_cert.pem" "$sig_file" "$original_file"
    
    if [ $? -eq 0 ]; then
        echo "✓ $original_file 验证成功"
    else
        echo "✗ $original_file 验证失败"
        exit 1
    fi
done

# 测试3: 避免重复签名
echo
echo "=== 测试3: 避免重复签名 ==="
./build/bin/file_signer -c "$CERT_DIR/ca_cert.pem" \
    -k "$CERT_DIR/ca_key.pem" \
    -i "$TEST_DIR" \
    -v 2>&1 | grep "已签名（跳过）"

if [ $? -eq 0 ]; then
    echo "✓ 避免重复签名测试通过"
else
    echo "✗ 避免重复签名测试失败"
fi

# 测试4: 强制重新签名
echo
echo "=== 测试4: 强制重新签名 ==="
./build/bin/file_signer -c "$CERT_DIR/ca_cert.pem" \
    -k "$CERT_DIR/ca_key.pem" \
    -i "$TEST_DIR" \
    -f -v 2>&1 | grep "已签名"

if [ $? -eq 0 ]; then
    echo "✓ 强制重新签名测试通过"
else
    echo "✗ 强制重新签名测试失败"
fi

# 清理测试文件
echo
echo "=== 清理测试文件 ==="
rm -f "$TEST_DIR"/*.txt "$TEST_DIR"/*.pdf "$TEST_DIR"/*.sig

echo
echo "=== 所有测试通过 ==="