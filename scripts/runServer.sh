#echo "running server"

ip_addr="128.0.0.1"
delay=0
f=""
while getopts ":h?:s:a:" opt; do
    case "$opt" in
        h|\?)
            echo -e "\nArguments: "
            echo -e "-s \t\t Server number (default 1)"
            echo -e "-a \t\t ip address to listen on"
            echo -e "-f \t\t log num files"
            exit 0
            ;;

        s)  
            server_num="$OPTARG"
            ;;
        a)
            ip_addr="$OPTARG"
            ;;
        f)  
            logFile="$OPTARG"
            ;;
    esac        
done    

CGO_CXXFLAGS="-O3" CGO_LDFLAGS="-lcrypto" go run src/server/server.go --ip=$ip_addr --config=src/config/server$server_num.config