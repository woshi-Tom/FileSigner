#!/bin/bash
# 生成测试证书

set -e

CERT_DIR="test/certificates"
mkdir -p "$CERT_DIR"

echo "生成根证书..."
openssl genrsa -out "$CERT_DIR/root_ca.key" 2048
openssl req -x509 -new -nodes -key "$CERT_DIR/root_ca.key" \
    -sha256 -days 3650 -out "$CERT_DIR/root_ca.pem" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Root CA/CN=Test Root CA"

echo "生成中间证书..."
openssl genrsa -out "$CERT_DIR/intermediate.key" 2048
openssl req -new -key "$CERT_DIR/intermediate.key" \
    -out "$CERT_DIR/intermediate.csr" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Intermediate CA/CN=Test Intermediate CA"

echo "使用根证书签名中间证书..."
openssl x509 -req -in "$CERT_DIR/intermediate.csr" \
    -CA "$CERT_DIR/root_ca.pem" -CAkey "$CERT_DIR/root_ca.key" \
    -CAcreateserial -out "$CERT_DIR/intermediate.pem" \
    -days 1825 -sha256

echo "生成签名证书（用于文件签名）..."
openssl genrsa -out "$CERT_DIR/signing.key" 2048
openssl req -new -key "$CERT_DIR/signing.key" \
    -out "$CERT_DIR/signing.csr" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Organization/CN=Test Signing Certificate"

echo "使用中间证书签名..."
openssl x509 -req -in "$CERT_DIR/signing.csr" \
    -CA "$CERT_DIR/intermediate.pem" -CAkey "$CERT_DIR/intermediate.key" \
    -CAcreateserial -out "$CERT_DIR/signing.pem" \
    -days 365 -sha256

echo "创建证书链..."
cat "$CERT_DIR/signing.pem" "$CERT_DIR/intermediate.pem" > "$CERT_DIR/ca_cert.pem"
cp "$CERT_DIR/signing.key" "$CERT_DIR/ca_key.pem"

echo "清理临时文件..."
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl

echo
echo "生成的证书文件:"
echo "  根证书:        $CERT_DIR/root_ca.pem"
echo "  中间证书:      $CERT_DIR/intermediate.pem"
echo "  签名证书链:    $CERT_DIR/ca_cert.pem"
echo "  签名私钥:      $CERT_DIR/ca_key.pem"

echo
echo "验证证书链:"
openssl verify -CAfile "$CERT_DIR/root_ca.pem" \
    -untrusted "$CERT_DIR/intermediate.pem" \
    "$CERT_DIR/signing.pem"