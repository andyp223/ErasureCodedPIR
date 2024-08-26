echo "Running Client"

bench_dir="outputs/sample.txt"
config_file_name="../config/client.config"
logNumFiles=8
fileSizeBytes=8
p=4
t=1
k=2
r=0
b=0
i=1
m=0
rho=1
mac=0
delayTime=0
numDelayedServer=0
logFile=""
d=0
swigTest="false"
correctnessTest="false"
numThreads=1
bandwidth=500

while getopts ":h?:t:l:o:y:k:c:r:b:i:a:m:f:x:n:z:w:" opt; do
    case "$opt" in
        h|\?)
            echo "\nArguments: "
            echo "-a \t\t ip addrs to listen at \n"
            echo "-n \t\t Number of delayed servers"
            echo "-k \t\t MDS threshold number of parties (default 1)\n"
            echo "-l \t\t Print latency breakdown (only for some options)\n"
            echo "-r \t\t Number of unresponsive servers\n"
            echo "-o \t\t Rho:Number of symbols downloaded each round\n"
            echo "-y \t\t CheckMAC\n"
            echo "-b \t\t Number of byzantine servers \n"
            echo "-m \t\t dpf function to use \n"
            echo "-x \t\t delay to use \n"
            echo "-c \t\t number of threads \n"
            echo "-w \t\t bandwidth limit \n"
            exit 0
            ;;
        x)
            delayTime=$OPTARG
            ;;
        n)  
            numDelayedServer=$OPTARG
            ;;
        c)
            numThreads=$OPTARG
            ;;
        l)
            logNumFiles=$OPTARG
            ;;
        t)
            t=$OPTARG
            ;;
        b)
            b=$OPTARG
            ;;
        k)
            k=$OPTARG
            ;;
        i)
            i=$OPTARG
            ;;
        a)
            ip_addrs=$OPTARG
            ;;
        m)
            m=$OPTARG
            ;;
        r)
            r=$OPTARG
            ;;
        f)
            fileSizeBytes=$OPTARG
            ;;
        z) 
            logFile=$OPTARG
            ;;
        w)
            bandwidth=$OPTARG
            ;;
        o)
            rho=$OPTARG
        ;;
        y)
            mac=$OPTARG
        ;;
    esac
done


echo "logNumFiles = $logNumFiles , fileSizeBytes=$fileSizeBytes "

CGO_CXXFLAGS="-O3" CGO_LDFLAGS="-lcrypto" go run src/benchmark/benchmark.go --config="src/config/client.config" --network=true --t=$t --logNumFiles=$logNumFiles --fileSizeBytes=$fileSizeBytes --k=$k --q=$i --ipAddrs=$ip_addrs --r=$r --b=$b --mode=$m --rho=$rho --mac=$mac --numDelay=$numDelayedServer --delayTime=$delayTime --logFile=$logFile --threads=$numThreads --bandwidth=$bandwidth