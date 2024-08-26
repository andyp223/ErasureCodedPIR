# ErasureCodedPIR

This implementation accompanies our paper "Communication-efficient, Fault Tolerant PIR over Erasure-Coded Storage" by Andrew Park, Trevor Leong,
Francisco Maturana, Wenting Zheng, and Rashmi Vinayak which appeared in Oakland '24. 

WARNING: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

# Running Locally

## With Docker(Preferred):
```
# In the root directory
./scripts/run_docker_end_to_end.sh
```

## Without Docker:
```
# In the root directory
export GO111MODULE=off
export GOPATH=$(pwd)
./scripts/run_end_to_end.sh
```

# Running experiments on AWS
## Set environment variables
```
export EAST_AMI="ami-08333bccc35d71140" # Do not change
export WEST_AMI="ami-051ed863837a0b1b6" # Do not change
export SECURITY_GROUP={YOUR AWS SECURITY GROUP}
export GH_USER={USER}
export GH_TOKEN={YOUR PERSONAL ACCESS TOKEN}
export AWS_ACCESS_KEY_ID={YOUR AWS ACCESS KEY}
export AWS_SECRET_ACCESS_KEY={YOUR SECRET ACCESS KEY}
```
## Run benchmarks
```
cd bench
# Install requirements
pip install -r requirements.txt
python run_tests.py -free 1
# Terminate AWS instances
# REMEMBER TO MANUALLY CHECK IF INSTANCES WERE SHUT DOWN
python teardown.py
```

# Running custom configurations
Instructions for running custom configurations can be done by passing the appropriate parameters in the benchmark() function in ```bench/run_tests.py```. For descriptions of each option, check out scripts/run_client.sh 
