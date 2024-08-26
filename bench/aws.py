import boto3
import os
import paramiko
import subprocess
import time
import socket

from dataclasses import dataclass

INSTANCE_TYPE_DEFAULT = "t2.micro"
 
@dataclass
class AWSConfig():
    username: str
    token: str
    access_key: str
    secret_access_key: str
    east_ami: str
    west_ami: str
    sec_groups: str

    def init_ec2_resources(self):
        self.ec2_east = boto3.resource("ec2",
                          aws_access_key_id=self.access_key,
                          aws_secret_access_key=self.secret_access_key,
                          region_name="us-east-2")

        self.ec2_west = boto3.resource("ec2",
                                aws_access_key_id=self.access_key,
                                aws_secret_access_key=self.secret_access_key,
                                region_name="us-west-1")

'''
    Initialize ec2 objects
'''
# Copied from: https://github.com/edwjchen/circ_benchmarks/blob/master/aws_controller.py
def create_instances(config,instances_to_create,instance_type=INSTANCE_TYPE_DEFAULT):
    # Create num_instancs_to_create EC2 instances on east
    instances = list(config.ec2_east.instances.filter(
        Filters=[{"Name": "instance-state-name",
                  "Values": ["stopping", "pending", "running", "stopped"]},
                 {"Name":"key-name",
                  "Values":["aws-east"]},
                {"Name":"instance-type",
                  "Values":[instance_type]}
                ]))
    
    num_instances_to_create = max(0,instances_to_create-len(instances))
    print(f"There are {num_instances_to_create} {instance_type} east instances to create, {len(instances)}")
    if num_instances_to_create > 0:
        config.ec2_east.create_instances(ImageId=config.east_ami,
                                  InstanceType=instance_type,
                                  KeyName="aws-east",
                                  MinCount=1,
                                  MaxCount=num_instances_to_create,
                                  Monitoring={
                                      "Enabled": False},
                                  SecurityGroupIds=config.sec_groups
                                  )
    print('done creating east instances')
    # Create num_instancs_to_create EC2 instances on west
    instances = list(config.ec2_west.instances.filter(
        Filters=[{"Name": "instance-state-name", "Values": ["stopping", "pending", "running", "stopped"]},
                 {"Name":"key-name","Values":["aws-west"]}]))
    if len(instances) == 0:
        config.ec2_west.create_instances(ImageId=config.west_ami,
                                    InstanceType=instance_type,
                                    KeyName="aws-west",
                                    MinCount=1,
                                    MaxCount=1,
                                    Monitoring={
                                        "Enabled": False},
                                    SecurityGroupIds=config.sec_groups,
                                    )

def stop_instances(config,region):
    ec2_instances = config.ec2_east if region == 'east' else config.ec2_west
    for instance in  list(ec2_instances.instances.filter()):
        ec2_instances.instances.filter(InstanceIds=[instance.id]).stop()
    print("Terminated everything")
    print("Stopped everything")
#stop_all_instances()



set_env_command = 'export GO111MODULE=off && export GOPATH=$(pwd)'


#CITE: Based on code from https://github.com/edwjchen/circ_benchmarks/blob/master/aws_controller.py
def setup_client(config,client):
    print("Setting up client")
    _, stdout, _ = client.exec_command(f"cd coded_pir")
    if stdout.channel.recv_exit_status():
        _, stdout, _ = client.exec_command(
            f"sudo yum install git -y && git clone https://{config.username}:{config.token}@github.com/andyp223/coded_pir.git")
        if stdout.channel.recv_exit_status():
            print("failed setup")

    _, stdout, _ = client.exec_command(f"cd coded_pir && sudo yum install go -y && export GO111MODULE=off && export GOPATH=$(pwd) && sudo yum install gcc-c++ -y && sudo yum install openssl-devel -y && sudo yum install swig -y")
    if stdout.channel.recv_exit_status():
            print("failed to install dependencies")

    stdin, stdout, stderr = client.exec_command(f"cd coded_pir && {set_env_command} && git pull -f https://{config.username}:{config.token}@github.com/andyp223/coded_pir.git main && git checkout -f main && go get github.com/hashicorp/go-msgpack/codec")
    lines=stdout.readlines()

    if stdout.channel.recv_exit_status():
        print("ERROR: ",stderr.readlines(),lines)
    else:
        print("LINES: ",lines)


def setup_servers(config,server,num,_timeout):
    _, stdout, _ = server.exec_command(f"cd coded_pir")
    if stdout.channel.recv_exit_status():
        _, stdout, _ = server.exec_command(
            f"sudo yum install git -y && git clone https://{config.username}:{config.token}@github.com/andyp223/coded_pir.git")
        if stdout.channel.recv_exit_status():
            print("failed setup")

    _, stdout, _ = server.exec_command(f"cd coded_pir && sudo yum install go -y && export GO111MODULE=off && export GOPATH=$(pwd) && sudo yum install gcc-c++ -y && sudo yum install openssl-devel -y && sudo yum install swig -y")
    if stdout.channel.recv_exit_status():
            print("failed to install dependencies")

    stdin, stdout, stderr = server.exec_command(f"cd coded_pir && {set_env_command} && git pull -f https://{config.username}:{config.token}@github.com/andyp223/coded_pir.git main && git checkout -f main && go get github.com/hashicorp/go-msgpack/codec")
    lines=stdout.readlines()
    if stdout.channel.recv_exit_status():
        print("ERROR: ",stderr.readlines(),stdout.readlines())
    
def setup_instances_for_benchmarking(config,instances_needed,region):
    print('setting up servers for benchmarking')
    ec2_instances = config.ec2_east if region == 'east' else config.ec2_west

    stopped_instances = list(ec2_instances.instances.filter(
         Filters=[{"Name": "instance-state-name", "Values": ["stopped"]},
                 {"Name":"key-name","Values":[f"aws-{region}"]}]))
    count = 0
    num = min(instances_needed,len(stopped_instances))

    #print(num)
    for i in range(num):
        instance = stopped_instances[i]
        ec2_instances.instances.filter(InstanceIds=[instance.id]).start()
        print(instance)
        wait_until_running_wrapper(instance)
        count += 1
    

    running_instances = list(ec2_instances.instances.filter(
    Filters=[{"Name": "instance-state-name", "Values": ["running"]},
              {"Name":"key-name","Values":[f"aws-{region}"]}]))

    print('Instances all up and running!')
    ips = [instance.public_dns_name for instance in running_instances]

    ip = ips[0]
    ids = [instance.id for instance in running_instances]
    id = ids[0]

    key = paramiko.Ed25519Key.from_private_key_file(f"aws-{region}.pem")

    #client = paramiko.SSHClient()
    #client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    #client.connect(hostname=ip, username="ec2-user", pkey=key)



    servers = [0 for _ in running_instances]
    threads = [None for _ in running_instances]
   
    for i in range(len(running_instances)):
        servers[i] = paramiko.SSHClient()
        servers[i].set_missing_host_key_policy(paramiko.AutoAddPolicy())
        servers[i].connect(hostname=ips[i], username="ec2-user", pkey=key)
        print(f"Setting up server: {i}")
        setup_servers(config,servers[i],i,30)
    
    #setup_client(config,client)
    
    for i in range(len(running_instances)):
        servers[i].close()
    #client.close()

def connect_to_instance(region,ip):
    key = paramiko.Ed25519Key.from_private_key_file(f"aws-{region}.pem")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=ip, username="ec2-user", pkey=key)
    return client


def run_command(ssh_client,cmd):
    stdin, stdout, stderr = ssh_client.exec_command(cmd)
    lines=stdout.readlines()
    
    if stdout.channel.recv_exit_status():
        print("ERROR: ",stderr.readlines())
    else:
        print(lines)


def scp_to_local(hostname,remote_dir,local_dir='.'):
    cmd = (f"scp -i aws-west.pem -o StrictHostKeyChecking=no ec2-user@{hostname}:{remote_dir} {local_dir}")
    process = subprocess.Popen(cmd, shell=True)
    process.wait()

def instance_to_ip(instance):
    instance_ip = instance.public_dns_name
    return instance_ip.split('.')[0][4:].replace('-','.')

def instance_to_hostname(instance):
    ip = instance_to_ip(instance)
    return f"ip-{ip.replace('.','-')}"

# Stop all instance
def stop_all_instances(config):
    instances = 0
    # stop east instances
    for instance in list(config.ec2_east.instances.filter(
        Filters=[{"Name": "instance-state-name", "Values": ["stopping", "pending", "running", "stopped"]},
                 {"Name":"key-name","Values":["aws-east"]}])):
        instances += 1
        config.ec2_east.instances.filter(InstanceIds=[instance.id]).stop()
    print(f"Stopped {instances} East instances")

    instances=0
    # stop west instances
    for instance in  list(config.ec2_west.instances.filter(
        Filters=[{"Name": "instance-state-name", "Values": ["stopping", "pending", "running", "stopped"]},
                 {"Name":"key-name","Values":["aws-west"]}])):
        config.ec2_west.instances.filter(InstanceIds=[instance.id]).stop()
    print(f"Stopped {instances} West instances")
#stop_all_instances()

def terminate_all_instances(config):

    instances = 0
    # terminate east instances
    for instance in  list(config.ec2_east.instances.filter()):
        config.ec2_east.instances.filter(InstanceIds=[instance.id]).terminate()
        instances += 1
    print(f"Terminated {instances} east instances")
    
    instances = 0
    # terminate west instances
    for instance in list(config.ec2_west.instances.filter()):
        config.ec2_west.instances.filter(InstanceIds=[instance.id]).terminate()
        instances += 1
    print(f"Terminated {instances} west instances")
#terminate_all_instances()


def wait_until_running_wrapper(instance):
    retries = 10
    retry_count = 0
    instance.start()
    print("Waiting for instance to exist")
    instance.wait_until_exists()
    print("Waiting until instance is running")
    instance.wait_until_running()
    while retry_count <= retries:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((instance.public_ip_address,22))
        if result == 0:
            print(f"Instance is UP & accessible on port 22, the IP address is: {instance.public_ip_address}")
            break
        else:
            print("instance is still down retrying . . . ")
            retry_count += 1
            time.sleep(1)