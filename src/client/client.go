package client

/*
#include<stdlib.h>
#include<string.h>
*/
import "C"
import (
	"c"
	"common"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"
)

var dummyMath = math.Pow(2, (float64)(3))

var (
	client          c.Client		
	clientLock      sync.Mutex
	config          common.ClientConfig
	across          int
	LogFile         *os.File
	numDelay        int
	serverDelayTime int
	numThreads      int
	bandwidth       int
)

/* Read in config file. */
//Cite: Copied from https://github.com/ucbrise/dory/blob/master/src/server/client.go
func setupConfig(filename string) (common.ClientConfig, error) {
	config := common.ClientConfig{}

	file, err := os.Open(filename)
	if err != nil {
		log.Printf("%s\n", filename)
		return config, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return config, err
	}
	return config, nil
}

/* Log latency to file in separate thread. */
func logLatency(latency time.Duration, tag string) {
	go func(latency time.Duration, tag string) {
		file, _ := os.Create(config.OutDir + "/" + strconv.Itoa(int(c.GetNUM_FILES())) + tag)
		defer file.Close()
		io.WriteString(file, latency.String())
	}(latency, tag)
}

func OpenConnection(address, port string) *common.Conn {
	conn, err := common.OpenConnection(address + port)
	if err != nil {
		log.Fatalln("Error opening connection to master: ", err)
		return nil
	}
	return conn
}

func CloseConnection(conn *common.Conn) {
	common.CloseConnection(conn)
}

// Formats parameters so they can be written to logFile
func genOutputString(queryType, delayTime, numDelayServer int, start_time, keys_time, query_time, decode_time time.Time, receiveLatency, serverLatency, sendLatency time.Duration) string {
	return fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
		queryType,
		delayTime,
		numDelayServer,
		c.GetLOG_NUM_FILES(),
		c.GetFILE_SIZE_BYTES(),
		c.GetK(),
		c.GetR(),
		c.GetB(),
		c.GetD(),
		c.GetT(),
		keys_time.Sub(start_time).Microseconds(),
		receiveLatency.Microseconds(),
		serverLatency.Microseconds(),
		sendLatency.Microseconds(),
		query_time.Sub(keys_time).Microseconds(),
		decode_time.Sub(query_time).Microseconds(),
		numThreads,
		bandwidth,
	)
}

func InitializeLogFile(f *os.File) {
	LogFile = f
}

func TestNetwork(msg string) (string, error) {
	var wg sync.WaitGroup
	p := c.GetNUM_PARTIES()
	wg.Add(p)

	//log.Printf("Sending test value: %v \n", msg)
	var respError error
	var resp common.TestResponse
	resps := make([]common.TestResponse, p)
	//Send out request
	for i := 0; i < p; i++ {

		//log.Println(config.Addr[0])
		go func(i int) {
			defer wg.Done()
			common.SendMessage(
				config.Addr[i]+config.Port[i],
				common.TEST_REQUEST,
				&common.TestRequest{
					Msg: msg,
				},
				&resps[i],
				&respError,
			)
		}(i)
	}

	wg.Wait()

	for i := 0; i < p; i++ {
		if resps[i].Msg != msg {
			return "", fmt.Errorf("Expected: %v, but got: %v from server %v\n", msg, resp.Msg[i], i)
		}
	}

	return resp.Msg, nil
}

func SetupServers(delayTime int) {

	serverDelayTime = delayTime

	p := c.GetNUM_PARTIES()
	var wg sync.WaitGroup

	resps := make([]common.SetupResponse, p)

	//Wait for all servers to respond
	wg.Add(p)
	//Send out Setup requests

	isByzantineArr := make([]int, p)
	if c.GetB() > 0 {
		rand.Seed(time.Now().UnixNano())
		randArr := rand.Perm(p)
		for _, r := range randArr[:c.GetB()] {
			isByzantineArr[r] = 1
		}
	}

	delayArr := make([]int, p)
	if numDelay > 0 {
		rand.Seed(time.Now().UnixNano())
		randArr := rand.Perm(p)
		for _, v := range randArr[:numDelay] {
			delayArr[v] = delayTime
		}
	}

	for i := 0; i < p; i++ {
		var respError error

		resps[i] = common.SetupResponse{}
		go func(i int) {
			defer wg.Done()
			common.SendMessage(
				config.Addr[i]+config.Port[i],
				common.SETUP_REQUEST,
				&common.SetupRequest{
					BenchmarkDir:  "",
					LogNumFiles:   uint(c.GetLOG_NUM_FILES()),
					FileSizeBytes: uint(c.GetFILE_SIZE_BYTES()),
					T:             c.GetT(),
					K:             c.GetK(),
					R:             c.GetR(),
					B:             c.GetB(),
					Rho:           c.GetRHO(),
					Mode:          c.GetMODE(),
					IsByzantine:   isByzantineArr[i],
					DelayTime:     delayArr[i],
					NumThreads:    numThreads,
					CheckMAC:      c.GetCHECK_MAC(),
				},
				resps[i],
				&respError,
			)
		}(i)

	}
	wg.Wait()
}

func Setup(configFile string, logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, mode, numDelayServer int, addrReplace []string, threads int, _bandwidth int) string {

	var err error

	fmt.Println("Starting initialization...")
	config, err = setupConfig(configFile)
	if err != nil {
		log.Println(configFile)
		log.Fatalln("Error retrieving config file: ", err)
		return ""
	}
	if err != nil {
		log.Fatal(err)
	}

	if len(addrReplace) > 1 {
		config.Addr = addrReplace
	}

	numDelay = numDelayServer

	client = c.NewClient()
	// across = encodeAcross
	numThreads = threads
	bandwidth = _bandwidth

	c.SetSystemParams(logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, mode)

	c.Initialize_client(client, (byte)(c.GetLOG_NUM_FILES()), (uint)(c.GetFILE_SIZE_BYTES()))

	log.Println("Finished initialization...")
	return config.OutDir + strconv.Itoa(logNumFiles) + "_docs_"
}
