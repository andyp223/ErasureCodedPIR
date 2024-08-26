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

func RunWoodruffQuery(
	req common.WoodruffSearchRequest,
	config      common.ServerConfig,
	s           c.Server,
	threads     int,
	isByzantine *int,
	delay       int,
	numThreads  int) (common.WoodruffSearchResponse, error) {
	
	start := time.Now()
	receive := time.Now()

	resultSize := c.GetWOODRUFF_M() + 1
	var index int

	//Little bit hacky, but using sizeof(&req) for sizeof pointer
	//num_rounds * encoded file size bytes

	result := (**byte)(C.malloc(C.size_t(resultSize) * C.size_t(unsafe.Sizeof(&req))))
	resultIndexable := unsafe.Slice(result, resultSize)

	for i := 0; i < resultSize; i++ {
		resultIndexable[i] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
	}

	key := (*byte)(C.CBytes(req.Key))
	defer C.free(unsafe.Pointer(key))

	// Allocate space for threading result array
	input := (***byte)(C.malloc(C.size_t(numThreads) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(input))

	InputIndexable := unsafe.Slice(input, C.int(numThreads))

	// Currently hacked to only work for non-derivative woodruff
	for i := 0; i < numThreads; i++ {
		InputIndexable[i] = (**byte)(C.malloc(C.size_t(1) * C.size_t(unsafe.Sizeof(&key))))
		tmpIndexable := unsafe.Slice(InputIndexable[i], C.int(1))
		defer C.free(unsafe.Pointer(InputIndexable[i]))
		for j := 0; j < 1; j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	// Run threads for query
	slice := c.GetNUM_ENCODED_FILES() / numThreads

	var wg sync.WaitGroup
	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func(index int) {
			defer wg.Done()
			c.RunWoodruffQueryThread(s,
				key,
				index,
				index*slice,
				(index+1)*slice,
				InputIndexable[index],
			)
		}(i)
	}

	wg.Wait()

	// Assemble responses
	c.AssembleWoodruffQueryThreadResults(s, input, numThreads, result)

	// Results are 2-D array, where there are |encoded file size| x |file size| rows and columns
	// results := C.GoBytes(unsafe.Pointer(*result),C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	finalResponse := make([][]byte, resultSize)

	for i := 0; i < resultSize; i++ {
		finalResponse[i] = C.GoBytes(unsafe.Pointer(resultIndexable[i]), C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	}

	// Add artificial delay
	elapsed := time.Now().Sub(start)
	time.Sleep(time.Duration(delay) * time.Second)

	resp := common.WoodruffSearchResponse{
		Results:       finalResponse,
		ServerLatency: elapsed,
		ReceiveTime:   receive,
	}

	c.FreeServer(s)
	send := time.Now()
	resp.SendTime = send
	return resp, nil
}