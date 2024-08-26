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

func HollantiQuery(index int) ([]byte, error) {

	start_time := time.Now()
	p := c.GetNUM_PARTIES()
	//q := c.Choose(p,c.GetT())

	keyLength := c.GetNUM_FILES()
	keys := (***byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(keys))
	keysIndexable := unsafe.Slice(keys, C.int(p))

	for i := 0; i < p; i++ {
		keysIndexable[i] = (**byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(keysIndexable[i]))
		tmpIndexable := unsafe.Slice(keysIndexable[i], c.GetNUM_ROUNDS())
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(keyLength)))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	c.GenerateHollantiQuery(client, index, keys)
	keys_time := time.Now()

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

	// Use Go Channels to manage which servers responded
	resps := make([]*common.HollantiSearchResponse, p)
	var serverLatency time.Duration
	var sendLatency time.Duration
	var receiveLatency time.Duration
	sendLatency = time.Microsecond
	receiveLatency = time.Microsecond
	res := make(chan int)
	count := 0
	errs := make([]error, p)

	//Send out requests
	for i := 0; i < int(p); i++ {
		var respError error
		resps[i] = &common.HollantiSearchResponse{}
		tmpIndexable := unsafe.Slice(keysIndexable[i], C.size_t(c.GetNUM_ROUNDS()))
		serverKey := make([][]byte, c.GetNUM_ROUNDS())
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			serverKey[j] = C.GoBytes(unsafe.Pointer(tmpIndexable[j]), C.int(keyLength))
		}
		go func(i int) {
			var err error
			defer func() {
				errs[i] = err
				res <- i

			}()

			s_time := time.Now()

			err = common.SendMessage(
				config.Addr[i]+config.Port[i],
				common.HOLLANTI_SEARCH_REQUEST,
				&common.HollantiSearchRequest{
					Key: serverKey,
				},
				resps[i],
				&respError,
			)

			r_time := time.Now()

			// if resps[i].ServerLatency > serverLatency {
			// 	serverLatency = resps[i].ServerLatency
			// }

			// if resps[i].ReceiveTime.Sub(s_time) > receiveLatency {
			// 	receiveLatency = resps[i].ReceiveTime.Sub(s_time)
			// }

			// if r_time.Sub(resps[i].SendTime) > sendLatency {
			// 	sendLatency = r_time.Sub(resps[i].SendTime)
			// }

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
		return nil, fmt.Errorf("Not enough valid responses %v %v", p-c.GetR(), errs)
	}
	query_time := time.Now()

	serverLatency /= time.Duration((p - c.GetR()))
	receiveLatency /= time.Duration((p - c.GetR()))
	sendLatency /= time.Duration((p - c.GetR()))

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
				//fmt.Printf("i:%v j:%v results:%v\n",i,j,resps[i].Results)
				tmpIndexable1 := unsafe.Slice(testResponsesIndexable[curr], c.GetNUM_ROUNDS())
				copy(unsafe.Slice(tmpIndexable1[j], c.GetENCODED_FILE_SIZE_BYTES()),
					resps[i].Results[j])
			}
			curr++
		}
	}

	finalResult := (*byte)(C.malloc(C.size_t(c.GetFILE_SIZE_BYTES())))

	c.AssembleHollantiResponses(client, (*byte)(C.CBytes(erasureIndexList)), testResponses, finalResult)

	decode_time := time.Now()

	//Write results to log file
	LogFile.WriteString(genOutputString(3, serverDelayTime, numDelay, start_time, keys_time, query_time, decode_time, receiveLatency, serverLatency, sendLatency))

	//C.memset(unsafe.Pointer(finalResult), 1, C.size_t(c.GetFILE_SIZE_BYTES()))
	return C.GoBytes(unsafe.Pointer(finalResult), C.int(c.GetFILE_SIZE_BYTES())), nil
}