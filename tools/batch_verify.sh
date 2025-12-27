#!/bin/bash
# 批量验证脚本

set -e

if [ $# -lt 2 ]; then
    echo "用法: $0 <证书文件> <目录> [输出文件]"
    echo "示例: $0 ca_cert.pem ./signed_documents verification.log"
    exit 1
fi

CERT_FILE="$1"
DIRECTORY="$2"
OUTPUT_FILE="${3:-verification_$(date +%Y%m%d_%H%M%S).log}"

if [ ! -f "$CERT_FILE" ]; then
    echo "错误: 证书文件不存在: $CERT_FILE"
    exit 1
fi

if [ ! -d "$DIRECTORY" ]; then
    echo "错误: 目录不存在: $DIRECTORY"
    exit 1
fi

echo "开始批量验证..."
echo "证书文件: $CERT_FILE"
echo "目标目录: $DIRECTORY"
echo "输出文件: $OUTPUT_FILE"
echo

TOTAL=0
VALID=0
INVALID=0

{
    echo "签名验证报告"
    echo "生成时间: $(date)"
    echo "证书文件: $(realpath "$CERT_FILE")"
    echo "目标目录: $(realpath "$DIRECTORY")"
    echo "=" * 80
    echo
} > "$OUTPUT_FILE"

# 查找所有签名文件
find "$DIRECTORY" -type f -name "*.sig" | while read SIG_FILE; do
    TOTAL=$((TOTAL + 1))
    
    ORIGINAL_FILE="${SIG_FILE%.sig}"
    BASENAME="$(basename "$ORIGINAL_FILE")"
    
    if [ ! -f "$ORIGINAL_FILE" ]; then
        echo "✗ $BASENAME (原始文件不存在)" | tee -a "$OUTPUT_FILE"
        INVALID=$((INVALID + 1))
        continue
    fi
    
    # 使用 verify_sig 验证
    if ./build/bin/verify_sig "$CERT_FILE" "$SIG_FILE" "$ORIGINAL_FILE" > /dev/null 2>&1; then
        echo "✓ $BASENAME" | tee -a "$OUTPUT_FILE"
        VALID=$((VALID + 1))
    else
        echo "✗ $BASENAME (签名无效)" | tee -a "$OUTPUT_FILE"
        INVALID=$((INVALID + 1))
    fi
done

{
    echo
    echo "=" * 80
    echo "验证摘要:"
    echo "  总文件数: $TOTAL"
    echo "  有效签名: $VALID"
    echo "  无效签名: $INVALID"
    echo
    echo "完成时间: $(date)"
} | tee -a "$OUTPUT_FILE"

echo
echo "验证报告已保存到: $OUTPUT_FILE"