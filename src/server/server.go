package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"bufio"
	"c"
	"common"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"server_util"
	"time"
	"github.com/hashicorp/go-msgpack/codec"
)

var (
	config      common.ServerConfig
	s           c.Server
	threads     int
	isByzantine *int
	delay       int
	numThreads  int
)

// Initialize Server with Configs specified in configs/server
// Cite: Copied from https://github.com/ucbrise/dory/blob/master/src/server/server.go
func setupConfig(filename string) (common.ServerConfig, error) {
	tmp := common.ServerConfig{}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return config, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&tmp)
	if err != nil {
		fmt.Println(err)
		return config, err
	}
	return tmp, nil
}

// Main Logic for handling incoming requests
// Cite: Modified version of same function from https://github.com/ucbrise/dory/blob/master/src/server/server.go
func handleConnection(conn net.Conn) {

	//Close connection when finished
	defer conn.Close()

	//Initialize encoder/decoder for network communication
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	dec := codec.NewDecoder(r, &codec.MsgpackHandle{})
	enc := codec.NewEncoder(w, &codec.MsgpackHandle{})

	for {
		rpcType, err := r.ReadByte()
		if err != nil {
			//log.Printf("ERROR IN rpcType: %v \n",err)
			if err.Error() == "EOF" {
				break
			} else {
				log.Fatalln(err)
				break
			}
		}

		switch rpcType {

		case common.SETUP_REQUEST:
			//fmt.Println("In SETUP")
			var req common.SetupRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()
			resp, respErr := setup(req)
			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}

		case common.TREE_SEARCH_REQUEST:
			var req common.TreeSearchRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()

			resp, respErr := server_util.RunTreeQuery(
				req,
				config,
				s,           
				threads,
				isByzantine,
				delay,
				numThreads)
			
			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}

		case common.SHAMIR_SEARCH_REQUEST:
			var req common.ShamirSearchRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()
			resp, respErr := server_util.RunShamirQuery(
				req,
				config,
				s,           
				threads,
				isByzantine,
				delay,
				numThreads)
			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			logLatency(elapsed, "semihonest")
			if err := enc.Encode(&respErr); err != nil {
				log.Printf("FAILED WHILE WRITING ERR")
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Printf("FAILED WHILE WRITING NORM")
				log.Println(err)
			}
			if err := w.Flush(); err != nil {
				log.Printf("FAILED WHILE FLUSHING")
				log.Println(err)
			}

		case common.MULTIPARTY_SEARCH_REQUEST:
			var req common.MultipartySearchRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()

			resp, respErr := server_util.RunMultipartyQuery(
				req,
				config,
				s,           
				threads,
				isByzantine,
				delay,
				numThreads)
			
			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}
		case common.HOLLANTI_SEARCH_REQUEST:
			var req common.HollantiSearchRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()

			resp, respErr := server_util.RunHollantiQuery(
				req,
				config,
				s,           
				threads,
				isByzantine,
				delay,
				numThreads)
			
			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}
		case common.CD732_SEARCH_REQUEST:
			var req common.CD732SearchRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()

			resp, respErr := server_util.RunCDQuery(
				req,
				config,
				s,           
				threads,
				isByzantine,
				delay,
				numThreads)
			
			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}
		case common.WOODRUFF_SEARCH_REQUEST:
			var req common.WoodruffSearchRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			start := time.Now()

			resp, respErr := server_util.RunWoodruffQuery(
				req,
				config,
				s,           
				threads,
				isByzantine,
				delay,
				numThreads)

			elapsed := time.Since(start)
			resp.ServerLatency = elapsed
			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}
		case common.TEST_REQUEST:
			var req common.TestRequest
			if err := dec.Decode(&req); err != nil {
				log.Fatalln(err)
			}
			resp, respErr := run_test(req)

			if err := enc.Encode(&respErr); err != nil {
				log.Fatalln(err)
			}
			if err := enc.Encode(&resp); err != nil {
				log.Fatalln(err)
			}
			if err := w.Flush(); err != nil {
				log.Fatalln(err)
			}

		default:
			log.Fatalln(fmt.Errorf("Unknown request type %d", rpcType))
		}
	}
}

/* Log latency to file in separate thread. */
// CITE: Copied from https://github.com/ucbrise/dory/blob/master/src/server/server.go
func logLatency(latency time.Duration, tag string) {
	go func(latency time.Duration, tag string) {
		//file, _ := os.Create(config.OutDir + "/" + strconv.Itoa(int(c.GetNUM_FILES())) + "_docs_" + tag)
		//defer file.Close()
		//io.WriteString(file, latency.String())
	}(latency, tag)
}

// Stores data in memory across or within files depending on
// the encodeAcross flag
func setup(req common.SetupRequest) (common.SetupResponse, error) {
	start := time.Now()
	tmp_client := c.NewClient()

	if req.CheckMAC == 1 {
		c.SetSystemParams(int(req.LogNumFiles), int(req.FileSizeBytes)-c.GetMAC_SIZE_BYTES(), req.T, req.K, req.R, req.B, req.Rho, req.CheckMAC, req.Mode)
	} else {
		c.SetSystemParams(int(req.LogNumFiles), int(req.FileSizeBytes), req.T, req.K, req.R, req.B, req.Rho, req.CheckMAC, req.Mode)
	}

	c.Initialize_client(tmp_client, (byte)(req.LogNumFiles), (uint)(req.FileSizeBytes))

	c.InitializeServer(s, config.PartyIndex, (uint)(c.GetLOG_NUM_FILES()), (uint)(c.GetENCODED_FILE_SIZE_BYTES()), req.IsByzantine, req.NumThreads)

	numThreads = req.NumThreads

	if c.GetENCODE_ACROSS() == 1 {
		c.Encode_across_files_server(tmp_client, s)
	} else {
		c.Encode_within_files_server(tmp_client, s)
	}

	//Set Delay time
	delay = req.DelayTime

	//fmt.Printf("log num files: %v\n",c.GetLOG_NUM_FILES())
	resp := common.SetupResponse{
		ServerLatency: time.Since(start),
	}

	c.Free_client(tmp_client)
	return resp, nil
}

func run_test(req common.TestRequest) (common.TestResponse, error) {
	return common.TestResponse{
		Msg: req.Msg,
	}, nil
} 



func main() {

	// /* Set up config */
	filename := flag.String("config", "src/config/server.config", "server config file")
	isByzantine = flag.Int("byzantine", 0, "Server Byzantine status")
	ip := flag.String("ip", "", "IP address to listen at")

	flag.Parse()

	var err error

	// Load in config
	config, err = setupConfig(*filename)

	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	//Override ip address if specified on command line
	if len(*ip) > 0 {
		config.Addr = *ip
	}

	// Allocate Server
	s = c.NewServer()
	defer c.DeleteServer(s)

	if err != nil {
		log.Fatalln("Error retrieving config file: ", err)
	}

	/* Initialize server */
	log.Println("Starting initialization...")

	/* Start listening */
	log.Printf("Server %v listening... at: %v \n", config.PartyIndex, config.Addr+config.Port)
	err = common.ListenLoop(config.Port, config.CertFile, config.KeyFile, handleConnection)
	if err != nil {
		log.Printf("err: %v", err)
		log.Fatalln(err)
	}

}
