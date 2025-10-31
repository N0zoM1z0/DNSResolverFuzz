## Overview
对原版环境做了更新和一些bug修复；
- 更新了部分server版本
- 将原版需要ipython手动交互的cluster.py改为直接运行的版本，同时添加了更多更详细的日志输出，以便分析
- 修复了部分原版本出现的bug，代码鲁棒性提升

在原来代码的基础上进行了一些扩展
- 新增了一些更强大的cache差异分析脚本（data_process/cache目录下的cache_insight_analyzer_v*.py），可以根据不同的filter条件进行差异分析，方便定位问题。
- 新增了根据指定json文件提取对应indexes的详细请求响应对比信息的脚本（data_process/cache/inspect_specific_indices.py），便于人工分析。

## Environment Setup
对部分server的版本进行了更新
- bind9 -> 9.18.41
- unbound -> 1.24.1
- maradns -> 这个有问题，原版也一直No Response
- powerdns -> 4.9.0

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

## Run

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
# 注意！！！！每次运行会清空之前结果！！！！！
sudo $PYTHON_PATH main_recursive.py --unit_size 2 --payload_num 2 > log.txt 2>&1
# ！！！！！！！！！！！！！！！！！！！！！！
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

# 没什么用的response差异分析
cd .. # data_process
python response_analyzer.py --res_folder ../test_infra/recursive_test_res --verbose > response_analysis_log.txt 2>&1

# cache差异分析
cd ../cache
# 原版本，添加了main函数。可以直接运行
python cache_analyzer.py --res_folder ../../test_infra/recursive_test_res

# 加了filter的更强大的版本
# 会自动生成 cache_insight_analysis_result 文件夹，里面有各个filter类型分析结果的json文件
# v1: CP1,CP2,R1~R5
python cache_insight_analyzer_v1.py --res_folder ../../test_infra/recursive_test_res > cache_insight_analysis_v1_log.txt 2>&1
# v2: CP1,CP2,CP4,R1~R7
python cache_insight_analyzer_v2.py --res_folder ../../test_infra/recursive_test_res > cache_insight_analysis_v2_log.txt 2>&1
# v3: CP1,CP2,CP4,R1~R7,(newly added by N0zoM1z0) CP5~CP22,RC8-RC22,CC2-CC8
python cache_insight_analyzer_v3.py --res_folder ../../test_infra/recursive_test_res > cache_insight_analysis_v3_log.txt 2>&1


# 详细分析结果
# inspect_specific_indices.py: 根据指定的json文件，提取对应indexes的详细请求响应对比信息，生成文本文件，便于人工分析
python3 inspect_specific_indices.py --res_folder ../../test_infra/recursive_test_res --json_file cache_insight_analysis_result/CP1.json > cp1_detailed_inspection.txt

```

## TODO
Q：能不能把这些库更新到最新版本？要解决依赖报错问题
- bind9 -> 9.18.41
- unbound -> 1.24.1
- maradns -> 这个有问题，原版也一直No Response
- powerdns -> 4.9.0