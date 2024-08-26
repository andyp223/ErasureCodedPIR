from mimetypes import init
import boto3
import json
import os
import sys
import time
import threading
import getopt
import aws
import argparse

VCPU_LIMIT = 128
INSTANCE_TYPE_FREE = "t2.micro" 
INSTANCE_TYPE_BENCHMARK = "r5.4xlarge"

INSTANCE_TYPE = INSTANCE_TYPE_FREE

LOGFILE="figure.csv"
# instance_type = "c5.large"
# COMPILE_INSTANCE_TYPE = "c5.large"
# COMPILE_INSTANCE_TYPE = "r5.4xlarge" # 16 cpus

LAN = "LAN"
WAN = "WAN"
EAST = "east"
WEST = "west"

BANDWIDTH_LIMIT = 500
NUM_INSTANCES = 16

EAST_AMI= os.environ.get("EAST_AMI","")
WEST_AMI = os.environ.get("WEST_AMI","")

USERNAME = os.environ.get("GH_USER","")
TOKEN = os.environ.get("GH_TOKEN","")

aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "")
aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "")

SECURITY_GROUP = os.environ.get("SECURITY_GROUP", "")

config = None

def setup_instances(num_instances):
    aws.create_instances(config,num_instances,INSTANCE_TYPE)

    aws.setup_instances_for_benchmarking(config,num_instances,'east')
    aws.setup_instances_for_benchmarking(config,num_instances,'west')

    running_east_instances = list(config.ec2_east.instances.filter(
    Filters=[{"Name": "instance-state-name", "Values": ["running"]},
            {"Name":"key-name","Values":["aws-east"]}]))[:num_instances]
    
    running_west_instances = list(config.ec2_west.instances.filter(
         Filters=[{"Name": "instance-state-name", "Values": ["running"]},
                 {"Name":"key-name","Values":["aws-west"]}]))

    instances = {}

    instances['client'] = running_west_instances[0]

    instances['east'] = running_east_instances

    return instances

set_env_command = 'export GO111MODULE=off && export GOPATH=$(pwd)'
set_tc_command = lambda bandwidth_limit:f"sudo yum install iproute-tc -y && sudo pip3 install tcconfig  && sudo setcap cap_net_admin+ep /usr/sbin/tc && sudo /usr/local/bin/tcdel eth0 --all && sudo /usr/local/bin/tcset eth0 --rate {bandwidth_limit}Kbps && tcshow eth0" 

def run_client(client,ips,logNumFiles,fileSizeBytes,_p,_t,_k,_r,_b,_i):
    time.sleep(5)
    print("Running Client")
    mod_ips = [ip.split('.')[0][4:].replace('-','.') for ip in ips]
    stdin, stdout, stderr = client.exec_command(f"cd coded_pir && {set_env_command}  && ./scripts/runClient.sh -f {fileSizeBytes} -l {logNumFiles} -p {_p} -t {_t} -k {_k} -r {_r} -b {_b} -i {_i} -a {','.join(mod_ips)} ")
    lines=stdout.readlines()
    
    '''
    if stdout.channel.recv_exit_status():
        print("CLIENT ERROR: ",stderr.readlines(),stdout.readlines())
    else:
        print("CLIENT LINES: ",lines)
    '''


def setup_server(region,index,ip):
    server = aws.connect_to_instance(region,ip)
    server.exec_command("pkill server")
    stdin, stdout, stderr = server.exec_command(f"cd coded_pir && {set_env_command}  &&  ./scripts/runServer.sh -s {index} -a {ip}")
    lines=stdout.readlines()
    
    '''
    if stdout.channel.recv_exit_status():
        print("SERVER ERROR: ",stderr.readlines())
    else:
        print("lines: ",lines)
    '''
    

def setup_servers(instances):

    threads = []
    all_ips = {}

    for i in range(len(instances['east'])):
        x = threading.Thread(target=setup_server, args=('east',i+1,aws.instance_to_ip(instances['east'][i]),))
        all_ips[i] = aws.instance_to_ip(instances['east'][i])
        threads.append(x)
        x.start()

    time.sleep(5)

    return all_ips
        
    


def benchmark_with_params(instances,all_ips_tmp,queryType,l,f,t,k,b,r,rho,checkMac,delay,numDelayedServer,numThreads,bandwidth):

    client = aws.connect_to_instance('west',aws.instance_to_ip(instances['client']))

    #print("client ip ",aws.instance_to_ip(instances['client']))
    all_ips = [all_ips_tmp[i] for i in range(len(instances['east']))]
    
    if b == 0:
        for _ in range(5):
            setup_servers(instances)
            #all_ips = [aws.instance_to_ip(i) for i in instances['east'] + instances['west']]
            # cmd = f"cd coded_pir && {set_env_command} && {set_tc_command(bandwidth)} && ./scripts/runClient.sh -l {l} -f {f} -k {k} -t {t} -r {r} -p {p} -a {','.join(all_ips)} -d {d} -n {numDelayedServer} -x {delay} -z {LOGFILE} -m {queryType} -c {numThreads} -w {bandwidth}"
            cmd = f"cd coded_pir && {set_env_command} && ./scripts/runClient.sh -l {l} -f {f} -k {k} -t {t} -r {r} -a {','.join(all_ips)} -n {numDelayedServer} -o {rho} -y {checkMac} -z {LOGFILE} -m {queryType} -c {numThreads} -w {bandwidth}"
            print(cmd)
            aws.run_command(client,cmd)

            cmd = "cd coded_pir && sudo /usr/local/bin/tcdel eth0 --all"
            aws.run_command(client,cmd)

            #aws.scp_to_local(instances['client'].public_dns_name ,f"./coded_pir/{LOGFILE}",f"{LOGFILE}")
            time.sleep(1)
    else:
        for _ in range(5):
            setup_servers(instances)
            #all_ips = [aws.instance_to_ip(i) for i in instances['east'] + instances['west']]
            # cmd = f"cd coded_pir && {set_env_command} && {set_tc_command(bandwidth)} && ./scripts/runClient.sh -l {l} -f {f} -k {k} -t {t} -r {r} -b {b} -p {p} -a {','.join(all_ips)} -d {d} -n {numDelayedServer} -x {delay} -z {LOGFILE} -m {queryType}  -c {numThreads} -w {bandwidth}"
            cmd = f"cd coded_pir && {set_env_command} && ./scripts/runClient.sh -l {l} -f {f} -k {k} -t {t} -r {r} -b {b} -a {','.join(all_ips)} -n {numDelayedServer} -o {rho} -y {checkMac} -z {LOGFILE} -m {queryType} -c {numThreads} -w {bandwidth}"
            aws.run_command(client,cmd)

            # cmd = "cd coded_pir && sudo /usr/local/bin/tcdel eth0 --all"
            # aws.run_command(client,cmd)

            #aws.scp_to_local(instances['client'].public_dns_name ,f"./coded_pir/{LOGFILE}",f"{LOGFILE}")
            time.sleep(1)
    aws.scp_to_local(instances['client'].public_dns_name ,f"./coded_pir/{LOGFILE}",f"{LOGFILE}")
    
    
def all_stopped():
        for instance in list(config.ec2_east.instances.filter()):
            if instance.state['Name'] != 'stopped' and instance.state['Name'] != 'terminated':
                return False
        return True

def transfer_data(queryType,mal):

        # Open scped files and write to aggregate file
        if mal:
            malicious_tmp= open(f"{queryType}_malicious.csv",'r')
            malicious = open(f"{queryType}_malicious_final.csv",'a')
            malicious.write(malicious_tmp.read())
            malicious_tmp.close()
            malicious.close()
        else:
            semihonest_tmp = open(f"{queryType}_semihonest.csv",'r')
            semihonest = open(f"{queryType}_semihonest_final.csv",'a')
            semihonest.write(semihonest_tmp.read())
            semihonest_tmp.close()
            semihonest.close()
        
# queryType,l,f,t,k,b,r,rho,checkMac,delay,numDelayedServer,numThreads,bandwidth
# 0: dpf, 1: multiparty, 2: shamir, 3: hollanti

def benchmark(queryType):
    params_to_run = [
        (0,16,256,1,4,2,0,4,0,0,0,16,500), # DPF Tree   
    ]

    print("setting up instances")
    instances = setup_instances(NUM_INSTANCES)


    client = aws.connect_to_instance('west',aws.instance_to_ip(instances['client']))
    # remove exisitng files from client
    aws.run_command(client,"cd coded_pir && rm *semihonest && rm *malicious")

    all_ips_tmp =  setup_servers(instances)
    print("setting up client")
    aws.setup_client(config,client)

    for params in params_to_run:
        print("Runninng new set of params") 
        # queryType,l,f,t,k,b,r,rho,checkMac,delay,numDelayedServer,numThreads,bandwidth
        benchmark_with_params(instances,all_ips_tmp,params[0],params[1],params[2],params[3],params[4],params[5],params[6],params[7],params[8],params[9],params[10],params[11],params[12])
    
    #transfer_data(query_map[params[8]],args.b > 0)


    # Stop all instances
    #aws.stop_all_instances()

    #Wait for all instances to be stopped
    # while not all_stopped():
    #   x=1
'''
    1. Spin up appropriate number of servers on each coast
    2. Check That all are up and running
    3. Choose 1 server in East coast to be script runner
    4. Run benchmarks
    5. SCP file down from script runner
'''

def init_parser():
    my_parser = argparse.ArgumentParser()
    my_parser.version = '1.0'
    my_parser.add_argument('-delay', action='store',type=int, default = 0)
    my_parser.add_argument('-free', action='store',type=int,default = 0)
    my_parser.add_argument('-m', action='store',type=str,default ="t")
    my_parser.add_argument('-logFile',action='store',type=str,default="test.csv")
    return my_parser

if __name__ == "__main__":
    if not all([aws_access_key_id,aws_secret_access_key,USERNAME,TOKEN,SECURITY_GROUP]):
        print(
            f"One of the following environment variables is false. Please ensure it has a value\n \
            AWS_ACCESS_KEY:{aws_access_key_id}\n AWS_SECRET_ACCESS_KEY{aws_access_key_id}\n GH_USER:{USERNAME}\n GH_TOKEN:{TOKEN}"
        )
        exit()
    # Config to pass to AWS functions
    config = aws.AWSConfig(USERNAME,TOKEN,aws_access_key_id,aws_secret_access_key,EAST_AMI,WEST_AMI,[SECURITY_GROUP])
    config.init_ec2_resources()

    valid = {"t":"dpftree","m":"multiparty","s":"shamir"}    
    # if nothing specified, default to dpftree
    parser = init_parser()
    #ignored for now
    args = parser.parse_args()
    if(args.free == 1):
        INSTANCE_TYPE=INSTANCE_TYPE_BENCHMARK
        print(f"USING {INSTANCE_TYPE_BENCHMARK} instances to benchmark")
    
    LOGFILE=args.logFile
    
    #benchmark(valid[args.m])
    aws.stop_all_instances(config)
    aws.terminate_all_instances(config)