package main

/*
#include <stdlib.h>
*/
import "C"
import (
	//"bufio"
	"c"
	"client"
	"crypto/hmac"
	//"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unsafe"
)

func runSwigTest() {
	log.Println("Running Swig overhead tests")
}


func WriteToFile(f *os.File, string_to_write string) {
	f.WriteString(string_to_write)
}

func main() {

	filename := flag.String("config", "../config/client.config", "Client configuration file")
	logFile := flag.String("logFile", "", "File to write log data")
	logNumFiles := flag.Int("logNumFiles", 20, "Log of the number of files")
	fileSizeBytes := flag.Int("fileSizeBytes", 16, "Number of bytes per file")
	mode := flag.Int("mode", 0, "Which DPF method to use")
	t := flag.Int("t", 1, "Shamir Threshold number of parties")
	k := flag.Int("k", 2, "MDS Threshold number of parties")
	r := flag.Int("r", 1, "Number of unresponsive servers")
	b := flag.Int("b", 0, "Number of byzantine servers")
	rho := flag.Int("rho", 1, "Number of symbols downloaded each round")
	queryIndex := flag.Int("q", 1, "index to query")
	swigTest := flag.Bool("swig", false, "Choose to run swig overhead tests")
	networkTest := flag.Bool("network", false, "Choose to run network tests")
	//correctnessTest := flag.Bool("correct", false, "Choose to run correctness tests")
	ipAddrs := flag.String("ipAddrs", "", "Specify ip addresses to use")
	numDelay := flag.Int("numDelay", 0, "Number of delayed servers")
	delayTime := flag.Int("delayTime", 0, "seconds to delay servers")
	numThreads := flag.Int("threads", 1, "number of threads to use per server")
	bandwidth := flag.Int("bandwidth", 500, "bandwidth limit")
	mac := flag.Int("mac", 0, "Whether to check macs")
	flag.Parse()

	var file string
	// Set encodeAcross depending on the protocol
	switch *mode {
	case 0:
		// DPFTREE

		if *b > 0 {
			file = "dpftree_malicious"
		} else {
			file = "dpftree_semihonest"
		}

	case 1:
		// MULTIPARTY
		if *b > 0 {
			file = "multiparty_malicious"
		} else {
			file = "multiparty_semihonest"
		}

	case 2:
		// SHAMIR
		if *b > 0 {
			file = "shamir_malicious"
		} else {
			file = "shamir_semihonest"
		}

	case 3:
		//HOLLANTI
		if *b > 0 {
			file = "hollanti_malicious"
		} else {
			file = "hollanti_semihonest"
		}

	case 4:
		// Multiparty with covering design
		if *b > 0 {
			file = "CD732_malicious"
		} else {
			file = "CD732_semihonest"
		}

	case 5:
		// Multiparty with covering design
		if *b > 0 {
			file = "woodruff_malicious"
		} else {
			file = "woodruff_semihonest"
		}
	
	case 6:
		// Goldberg

		*k = 1
		if *b > 0 {
			file = "goldberg_malicious"
		} else {
			file = "goldberg_semihonest"
		}
	}

	if *logFile != "" {
		file = *logFile
		//log.Printf("logFile :%v\n",file)
	}

	client.Setup(*filename,
		*logNumFiles,
		*fileSizeBytes,
		*t,
		*k,
		*r,
		*b,
		*rho,
		*mac,
		*mode,
		*numDelay,
		strings.Split(*ipAddrs, ","),
		*numThreads,
		*bandwidth,
	)

	if *swigTest {
		runSwigTest()
	}

	if *networkTest {
		if _, err := client.TestNetwork("poke"); err != nil {
			os.Exit(1)
		} else {
			fmt.Printf("Servers all responding \n")
		}
	}

	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)

	client.InitializeLogFile(f)
	if err != nil {
		log.Fatal(err)
	}

	client.SetupServers(*delayTime)
	start := time.Now()
	var res []byte

	// Send out query of approapriate type
	switch *mode {
	case 0:
		res, err = client.TreeQuery(*queryIndex)
	case 1:
		res, err = client.MultipartyQuery(*queryIndex)
	case 2:
		res, err = client.ShamirQuery(*queryIndex)
	case 3:
		res, err = client.HollantiQuery(*queryIndex)
	case 4:
		res, err = client.CD732Query(*queryIndex)
	case 5:
		res, err = client.WoodruffQuery(*queryIndex)
	case 6:
		if c.GetK() != 1 {
			log.Fatal("K should be 1 in Goldberg scheme")
		}
		res, err = client.HollantiQuery(*queryIndex)
	default:
		_, err = client.TreeQuery(*queryIndex)
	}

	defer f.Close()

	if err != nil {
		fmt.Printf("Didn't work: %v\n", err)
	} else {
		if c.GetCHECK_MAC() == 1 {
			mac_size := c.GetMAC_SIZE_BYTES()
			mac_key := (*byte)(C.CBytes([]byte("1234567812345678")))

			original_msg := (*byte)(C.CBytes(res[:c.GetPAYLOAD_SIZE_BYTES()]))
			result_mac := (*byte)(C.malloc(C.size_t(mac_size)))
			defer C.free(unsafe.Pointer(result_mac))

			c.Mac(mac_key, original_msg, int(c.GetPAYLOAD_SIZE_BYTES()),
				result_mac, mac_size)
			final_mac := C.GoBytes(unsafe.Pointer(result_mac), C.int(mac_size))

			if !hmac.Equal(final_mac, res[len(res)-32:]) {
				log.Printf("MAC didnt verify: %v != %v", final_mac, res[len(res)-32:])
			} else {
				log.Printf("Great Success!!!\n")
			}
		}

		fmt.Printf("SUCCESS. TIME TAKEN FOR END_TO_END IS: %v \n", time.Since(start))
	}

}
