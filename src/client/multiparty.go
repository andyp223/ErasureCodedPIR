package client

/*
#include<stdlib.h>
#include<string.h>
*/
import "C"
import (
	"c"
	"common"
	"fmt"
	"time"
	"unsafe"
)

func MultipartyQuery(index int) ([]byte, error) {

	start_time := time.Now()
	p := c.GetNUM_PARTIES()
	num_rss_keys := c.GetNUM_RSS_KEYS()

	keyLength := c.CalcMultiPartyOptDPFKeyLength(p, c.GetLOG_NUM_ENCODED_FILES(), c.GetT())

	//Allocate Keys
	keys := (**byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(keys))
	keysIndexable := unsafe.Slice(keys, C.int(p))

	for j := 0; j < p; j++ {
		keysIndexable[j] = (*byte)(C.malloc(C.size_t(keyLength)))
		defer C.free(unsafe.Pointer(keysIndexable[j]))
	}

	//Allocate a responses vector
	responses := (***byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(responses))
	responsesIndexable := unsafe.Slice(responses, C.int(p))

	for i := 0; i < p; i++ {
		responsesIndexable[i] = (**byte)(C.malloc(C.size_t(num_rss_keys) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(responsesIndexable[i]))
		tmpIndexable := unsafe.Slice(responsesIndexable[i], num_rss_keys)
		for j := 0; j < num_rss_keys; j++ {
			tmpIndexable[j] = (*byte)(C.calloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES()), 1))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	c.GenerateMultiPartyDPFQuery(client, index, &keys)
	keys_time := time.Now()

	// Use Go Channels to manage which servers responded
	resps := make([]*common.MultipartySearchResponse, p)
	var serverLatency time.Duration
	res := make(chan int)
	count := 0
	errs := make([]error, p)
	var sendLatency time.Duration
	var receiveLatency time.Duration
	sendLatency = time.Microsecond
	receiveLatency = time.Microsecond

	//Send out requests
	for i := 0; i < int(p); i++ {
		var respError error
		resps[i] = &common.MultipartySearchResponse{}
		serverKey := C.GoBytes(unsafe.Pointer(keysIndexable[i]), C.int(keyLength))
		go func(i int) {
			var err error
			defer func() {
				errs[i] = err
				res <- i
			}()

			s_time := time.Now()

			err = common.SendMessage(
				config.Addr[i]+config.Port[i],
				common.MULTIPARTY_SEARCH_REQUEST,
				&common.MultipartySearchRequest{
					Key: serverKey,
				},
				resps[i],
				&respError,
			)
			r_time := time.Now()

			serverLatency += resps[i].ServerLatency
			receiveLatency += resps[i].ReceiveTime.Sub(s_time)
			sendLatency += r_time.Sub(resps[i].SendTime)

		}(i)

	}

	erasureIndexList := make([]byte, p)
	var returnedIndex int
	responded := 0

	for {
		returnedIndex = <-res
		responded += 1
		if errs[returnedIndex] == nil || errs[returnedIndex].Error() == "EOF" {
			count++
			erasureIndexList[returnedIndex] = 1
		}
		if responded == p || count == p-c.GetR() {
			break
		}
	}

	// Ensure there are enough responses to reconstruct.
	if count < p-c.GetR() {
		return nil, fmt.Errorf("Not enough valid responses")
	}
	query_time := time.Now()

	serverLatency /= time.Duration((p - c.GetR()))
	receiveLatency /= time.Duration((p - c.GetR()))
	sendLatency /= time.Duration((p - c.GetR()))

	testResponses := (***byte)(C.malloc(C.size_t(C.size_t(p-c.GetR()) * C.size_t((unsafe.Sizeof(&index))))))
	defer C.free(unsafe.Pointer(testResponses))
	testResponsesIndexable := unsafe.Slice(testResponses, C.int(p-c.GetR()))

	// Allocate C byte arrays from Go responses.
	for i := 0; i < p-c.GetR(); i++ {
		testResponsesIndexable[i] = (**byte)(C.malloc(C.size_t(num_rss_keys) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(testResponsesIndexable[i]))
		tmpIndexable := unsafe.Slice(testResponsesIndexable[i], num_rss_keys)
		for j := 0; j < num_rss_keys; j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	curr := 0
	for i := 0; i < p; i++ {
		if erasureIndexList[i] != 0 {
			tmpIndexable1 := unsafe.Slice(testResponsesIndexable[curr], num_rss_keys)
			for j := 0; j < num_rss_keys; j++ {
				//fmt.Printf("i:%v j:%v results:%v\n",i,j,resps[i].Results)
				copy(unsafe.Slice(tmpIndexable1[j], c.GetENCODED_FILE_SIZE_BYTES()),
					resps[i].Results[j])
			}
			curr++
		}
	}

	finalResult := (*byte)(C.malloc(C.size_t(c.GetFILE_SIZE_BYTES())))
	C.memset(unsafe.Pointer(finalResult), 0, C.size_t(c.GetFILE_SIZE_BYTES()))

	c.AssembleMultiPartyResponses(client, (*byte)(C.CBytes(erasureIndexList)), testResponses, finalResult)

	decode_time := time.Now()

	//Write results to log files
	LogFile.WriteString(genOutputString(1, serverDelayTime, numDelay, start_time, keys_time, query_time, decode_time, receiveLatency, serverLatency, sendLatency))

	defer C.free(unsafe.Pointer(finalResult))

	return C.GoBytes(unsafe.Pointer(finalResult), C.int(c.GetFILE_SIZE_BYTES())), nil

}