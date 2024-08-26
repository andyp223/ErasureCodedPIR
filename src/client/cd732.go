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

func CD732Query(index int) ([]byte, error) {

	start_time := time.Now()
	p := c.GetNUM_PARTIES()
	//num_rss_keys := c.GetNUM_RSS_KEYS()
	//q := c.Choose(p,c.GetT())

	keyLength := c.CalcCDDPFKeyLength(p, c.GetLOG_NUM_ENCODED_FILES(), c.GetT(), c.GetNUM_CD_KEYS_NEEDED(), c.GetNUM_CD_KEYS())

	//Allocate Keys
	//uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
	// fmt.Printf("Setting up keys %v\n\n", keyLength)
	keys := (**byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(keys))
	keysIndexable := unsafe.Slice(keys, p)

	for j := 0; j < p; j++ {
		keysIndexable[j] = (*byte)(C.malloc(C.size_t(keyLength)))
		defer C.free(unsafe.Pointer(keysIndexable[j]))
	}

	//Allocate a responses vector
	responses := (***byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(responses))
	responsesIndexable := unsafe.Slice(responses, C.int(p))

	for i := 0; i < p; i++ {
		responsesIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_CD_KEYS()) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(responsesIndexable[i]))
		tmpIndexable := unsafe.Slice(responsesIndexable[i], c.GetNUM_CD_KEYS())
		for j := 0; j < c.GetNUM_CD_KEYS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	c.GenerateCDQuery(client, index, &keys)
	keys_time := time.Now()

	// Use Go Channels to manage which servers responded
	resps := make([]*common.CD732SearchResponse, p)
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
		resps[i] = &common.CD732SearchResponse{}
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
				common.CD732_SEARCH_REQUEST,
				&common.CD732SearchRequest{
					Key: serverKey,
				},
				resps[i],
				&respError,
			)
			r_time := time.Now()

			// if resps[i].ServerLatency > serverLatency {
			// 	serverLatency = resps[i].ServerLatency
			// }
			// //log.Printf(" s_time: %v resps[i].ReceiveTime %v difference: %v\n", s_time,resps[i].ReceiveTime,resps[i].ReceiveTime.Sub(s_time).Microseconds())
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
	//log.Printf("difference: %v %v %v\n", receiveLatency.Microseconds(),sendLatency,serverLatency)
	// TODO: Find way to recieve all threads wihtout incurring overhead
	erasureIndexList := make([]byte, p)
	var returnedIndex int
	responded := 0

	for {
		returnedIndex = <-res
		responded += 1
		if errs[returnedIndex] == nil || errs[returnedIndex].Error() == "EOF" {
			count++
			erasureIndexList[returnedIndex] = 1
			// log.Printf("%v Response: %v \n",returnedIndex,resps[returnedIndex])
		}
		if responded == p || count == p-c.GetR() {
			break
		}
	}
	if count < p-c.GetR() {
		return nil, fmt.Errorf("Not enough valid responses")
	}

	serverLatency /= time.Duration((p - c.GetR()))
	receiveLatency /= time.Duration((p - c.GetR()))
	sendLatency /= time.Duration((p - c.GetR()))

	query_time := time.Now()

	testResponses := (***byte)(C.malloc(C.size_t(C.size_t(p-c.GetR()) * C.size_t((unsafe.Sizeof(&index))))))
	defer C.free(unsafe.Pointer(testResponses))
	testResponsesIndexable := unsafe.Slice(testResponses, C.int(p-c.GetR()))

	for i := 0; i < p-c.GetR(); i++ {
		testResponsesIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_CD_KEYS()) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(testResponsesIndexable[i]))
		tmpIndexable := unsafe.Slice(testResponsesIndexable[i], c.GetNUM_CD_KEYS())
		for j := 0; j < c.GetNUM_CD_KEYS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))

			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}
	curr := 0
	for i := 0; i < p; i++ {
		if erasureIndexList[i] != 0 {
			tmpIndexable1 := unsafe.Slice(testResponsesIndexable[curr], c.GetNUM_CD_KEYS())
			for j := 0; j < c.GetNUM_CD_KEYS(); j++ {
				//fmt.Printf("i:%v j:%v results:%v\n",i,j,resps[i].Results)

				copy(unsafe.Slice(tmpIndexable1[j], c.GetENCODED_FILE_SIZE_BYTES()),
					resps[i].Results[j])

				//log.Printf("RESULTS: %v %v %v \n\n\n",i,j,resps[i].Results[j])

			}
			curr++
		}
	}

	finalResult := (*byte)(C.malloc(C.size_t(c.GetFILE_SIZE_BYTES())))

	C.memset(unsafe.Pointer(finalResult), 0, C.size_t(c.GetFILE_SIZE_BYTES()))
	c.AssembleCDResponses(client, (*byte)(C.CBytes(erasureIndexList)), testResponses, finalResult)

	decode_time := time.Now()
	//Write results to log files
	LogFile.WriteString(genOutputString(4, serverDelayTime, numDelay, start_time, keys_time, query_time, decode_time, receiveLatency, serverLatency, sendLatency))

	defer C.free(unsafe.Pointer(finalResult))

	//C.memset(unsafe.Pointer(finalResult), 1, C.size_t(c.GetFILE_SIZE_BYTES()))

	return C.GoBytes(unsafe.Pointer(finalResult), C.int(c.GetFILE_SIZE_BYTES())), nil

}