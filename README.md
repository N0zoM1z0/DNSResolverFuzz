```bash
docker network create --subnet "172.22.0.0/16" test_net_batch
ip addr # 找172.22.0.0/16对应的 br-545f5f9d6df3
sudo iptables -I FORWARD -i br-545f5f9d6df3 -p icmp -j DROP

sudo iptables -I FORWARD -i br-e24d69e9543e -p icmp -j DROP
```

```bash
bash build.sh
# 单独构建某个镜像
sudo docker build -t resolverfuzz-powerdns:5.2.6 -f resolverfuzz-powerdns.Dockerfile .
```

test_infra

```bash
cd test_infra
conda activate resolverfuzz

# 在llmft机子需要改 /opt/miniconda-24.9.2/envs/resolverfuzz/lib/python3.8/site-packages/scapy/arch/bpf/core.py
# LIBC = cdll.LoadLibrary(find_library("libc"))
# 改为
# from ctypes import cdll
# LIBC = cdll.LoadLibrary("/usr/lib/x86_64-linux-gnu/libc.so.6")
PYTHON_PATH=$(which python)
sudo $PYTHON_PATH main_recursive.py --unit_size 2 --payload_num 2 > log.txt 2>&1

ls -R recursive_test_res

```

data_process（differential analysis）

```bash
cd ../data_process
sudo chown -R llmft:llmft ../test_infra/recursive_test_res # sudo chown -R work:work ../test_infra/recursive_test_res

python parser_query.py --res_folder ../test_infra/recursive_test_res
python parser_response.py --res_folder ../test_infra/recursive_test_res

cd traffic
python traffic_oracle.py --res_folder ../../test_infra/recursive_test_res

cd ../cache
python cache_analyzer.py --res_folder ../../test_infra/recursive_test_res

```

Q：能不能把这些库更新到最新版本？要解决依赖报错问题
- bind9 -> 9.18.41
- unbound -> 1.24.1
- maradns -> 这个有问题，原版也一直No Response
- powerdns -> 4.9.0