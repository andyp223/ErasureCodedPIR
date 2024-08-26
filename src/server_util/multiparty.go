package server_util

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"c"
	"common"
	"sync"
	"time"
	"unsafe"
)

func RunMultipartyQuery(
	req common.MultipartySearchRequest,
	config      common.ServerConfig,
	s           c.Server,
	threads     int,
	isByzantine *int,
	delay       int,
	numThreads  int) (common.MultipartySearchResponse, error) {
		receive := time.Now()
		start := time.Now()
	
		//Little bit hacky, but using sizeof(&req) for sizeof pointer
		//num_rounds * encoded file size bytes
	
		result := (**byte)(C.malloc(C.size_t(c.GetNUM_RSS_KEYS()) * C.size_t(unsafe.Sizeof(&req))))
		resultIndexable := unsafe.Slice(result, c.GetNUM_RSS_KEYS())
		defer C.free(unsafe.Pointer(result))
	
		for i := 0; i < c.GetNUM_RSS_KEYS(); i++ {
			resultIndexable[i] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(resultIndexable[i]))
		}
	
		key := (*byte)(C.CBytes(req.Key))
	
		// Allocate space for threading result array
		input := (***byte)(C.malloc(C.size_t(numThreads) * C.size_t(unsafe.Sizeof(&key))))
		defer C.free(unsafe.Pointer(input))
	
		InputIndexable := unsafe.Slice(input, C.int(numThreads))
	
		for i := 0; i < numThreads; i++ {
			InputIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_RSS_KEYS()) * C.size_t(unsafe.Sizeof(&key))))
			tmpIndexable := unsafe.Slice(InputIndexable[i], C.int(c.GetNUM_RSS_KEYS()))
			//defer C.free(unsafe.Pointer(InputIndexable[i]))
			for j := 0; j < c.GetNUM_RSS_KEYS(); j++ {
				tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
				//defer C.free(unsafe.Pointer(tmpIndexable[j]))
			}
		}
	
		// Run threads for query
		var wg sync.WaitGroup
		wg.Add(numThreads)
	
		for i := 0; i < numThreads; i++ {
			go func(index int) {
				defer wg.Done()
				c.RunOptimizedMultiPartyDPFQueryThread(s,
					key,
					index,
					numThreads,
					InputIndexable[index],
				)
			}(i)
		}
	
		wg.Wait()
	
		// Assemble responses
		c.AssembleMultipartyDPFQueryThreadResults(s, input, numThreads, result)
	
		// Results are 2-D array, where there are |encoded file size| x |file size| rows and columns
		resultsIndexable := unsafe.Slice(result, c.GetNUM_RSS_KEYS())
		finalResponse := make([][]byte, c.GetNUM_RSS_KEYS())
	
		for i := 0; i < c.GetNUM_RSS_KEYS(); i++ {
			finalResponse[i] = C.GoBytes(unsafe.Pointer(resultsIndexable[i]), C.int(c.GetENCODED_FILE_SIZE_BYTES()))
		}
	
		// Add artificial delay
		elapsed := time.Now().Sub(start)
		time.Sleep(time.Duration(delay) * time.Second)
	
		C.free(unsafe.Pointer(key))
		resp := common.MultipartySearchResponse{
			Results:       finalResponse,
			ServerLatency: elapsed,
			ReceiveTime:   receive,
		}
	
		c.FreeServer(s)
		send := time.Now()
		resp.SendTime = send
		return resp, nil
	}