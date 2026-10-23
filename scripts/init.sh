#!/usr/bin/env bash
# 生成两个 .env 文件里的随机密钥。已经存在的文件不会覆盖。
set -euo pipefail
cd "$(dirname "$0")/.."

rand_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
rand_alnum() { LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c "$1"; }

if [ ! -f .env ]; then
	cat >.env <<EOF
CROWDSEC_BOUNCER_KEY=$(rand_hex 24)
EOF
	chmod 600 .env
	echo "已生成 .env"
fi

if [ ! -f safeline/.env ]; then
	case "$(uname -m)" in
	arm64 | aarch64) arch_suffix=-arm ;;
	*) arch_suffix= ;;
	esac
	cat >safeline/.env <<EOF
IMAGE_PREFIX=chaitin
IMAGE_TAG=9.4.3
ARCH_SUFFIX=$arch_suffix
MGT_PORT=9443
SUBNET_PREFIX=172.22.222
POSTGRES_PASSWORD=$(rand_alnum 32)
DETECTOR_MGMT_TOKEN=$(rand_hex 32)
DETECTOR_AES_KEY=$(rand_alnum 16)
MGT_INTERNAL_TOKEN=$(rand_hex 32)
EOF
	chmod 600 safeline/.env
	echo "已生成 safeline/.env"
fi
