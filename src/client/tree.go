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

func TreeQuery(index int) ([]byte, error) {
	start_time := time.Now()
	//NumParties
	p := c.GetNUM_PARTIES()

	// Allocate appropriate resources
	keyLength := c.CalcOptimizedDPFTreeKeyLength(c.GetNUM_PARTIES(), c.GetLOG_NUM_ENCODED_FILES(), c.GetNUM_ROUNDS())
	
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
		responsesIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(responsesIndexable[i]))
		tmpIndexable := unsafe.Slice(responsesIndexable[i], c.GetNUM_ROUNDS())
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	// Key time includes:
	// 1. Party calculation
	// 2. Key array allocation
	// 3. Response Allocation
	// 4. Key generation
	c.Generate_opt_DPF_tree_query(client, index, &keys)
	keys_time := time.Now()

	resps := make([]*common.TreeSearchResponse, int(p))

	var serverLatency time.Duration

	// Use Go Channels to manage which servers responded
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
		resps[i] = &common.TreeSearchResponse{}
		serverKey := C.GoBytes(unsafe.Pointer(keysIndexable[i]), C.int(keyLength))
		go func(i int) {
			var err error
			defer func() {
				res <- i
				errs[i] = err
			}()

			s_time := time.Now()
			err = common.SendMessage(
				config.Addr[i]+config.Port[i],
				common.TREE_SEARCH_REQUEST,
				&common.TreeSearchRequest{
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
	if count < p-c.GetR() {
		return nil, fmt.Errorf("Not enough valid responses")
	}

	//log.Printf("combined serverLatency is: %v  Average: %v num_people: %v\n",serverLatency,serverLatency / time.Duration((p-c.GetR())), p-c.GetR());
	serverLatency /= time.Duration((p - c.GetR()))
	receiveLatency /= time.Duration((p - c.GetR()))
	sendLatency /= time.Duration((p - c.GetR()))

	// Query time includes:
	// 1. Request generation
	// 2. Request sending
	// 3. Key generation
	query_time := time.Now()

	testResponses := (***byte)(C.malloc(C.size_t(C.size_t(p-c.GetR()) * C.size_t((unsafe.Sizeof(&index))))))
	defer C.free(unsafe.Pointer(testResponses))
	testResponsesIndexable := unsafe.Slice(testResponses, C.int(p-c.GetR()))

	for i := 0; i < p-c.GetR(); i++ {
		testResponsesIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(testResponsesIndexable[i]))
		tmpIndexable := unsafe.Slice(testResponsesIndexable[i], c.GetNUM_ROUNDS())
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	curr := 0
	for i := 0; i < p; i++ {
		if erasureIndexList[i] != 0 {
			for j := 0; j < c.GetNUM_ROUNDS(); j++ {
				tmpIndexable1 := unsafe.Slice(testResponsesIndexable[curr], c.GetNUM_ROUNDS())
				copy(unsafe.Slice(tmpIndexable1[j], c.GetENCODED_FILE_SIZE_BYTES()),
					resps[i].Results[j])

			}
			curr++
		}
	}

	finalResult := (*byte)(C.malloc(C.size_t(c.GetFILE_SIZE_BYTES())))
	c.AssembleDPFTreeQueryResponses(client, (*byte)(C.CBytes(erasureIndexList)), testResponses, finalResult)

	decode_time := time.Now()

	LogFile.WriteString(genOutputString(0, serverDelayTime, numDelay, start_time, keys_time, query_time, decode_time, receiveLatency, serverLatency, sendLatency))
	
	return C.GoBytes(unsafe.Pointer(finalResult), C.int(c.GetFILE_SIZE_BYTES())), nil
}
