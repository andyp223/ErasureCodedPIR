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

func RunCDQuery(
	req common.CD732SearchRequest,
	config      common.ServerConfig,
	s           c.Server,
	threads     int,
	isByzantine *int,
	delay       int,
	numThreads  int) (common.CD732SearchResponse, error) {
	// void runOptimizedDPFTreeQuery(server *s, uint8_t* key, int numQueries, uint8_t** result);
	receive := time.Now()
	start := time.Now()

	//Little bit hacky, but using sizeof(&req) for sizeof pointer
	//num_rounds * encoded file size bytes
	result := (**byte)(C.malloc(C.size_t(c.GetNUM_CD_KEYS()) * C.size_t(unsafe.Sizeof(&req))))
	resultIndexable := unsafe.Slice(result, c.GetNUM_CD_KEYS())
	defer C.free(unsafe.Pointer(result))

	for i := 0; i < c.GetNUM_CD_KEYS(); i++ {
		resultIndexable[i] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
		defer C.free(unsafe.Pointer(resultIndexable[i]))
	}

	key := (*byte)(C.CBytes(req.Key))

	// Allocate space for threading result array
	input := (***byte)(C.malloc(C.size_t(numThreads) * C.size_t(unsafe.Sizeof(&req))))
	defer C.free(unsafe.Pointer(input))

	InputIndexable := unsafe.Slice(input, C.int(numThreads))

	for i := 0; i < numThreads; i++ {
		InputIndexable[i] = (**byte)(C.malloc(C.size_t(unsafe.Sizeof(&req)) * C.size_t(c.GetNUM_CD_KEYS())))
		tmpIndexable := unsafe.Slice(InputIndexable[i], c.GetNUM_CD_KEYS())
		defer C.free(unsafe.Pointer(InputIndexable[i]))
		for j := 0; j < c.GetNUM_CD_KEYS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	// Run threads for query

	var wg sync.WaitGroup
	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func(index int) {
			defer wg.Done()
			c.RunCDQueryThread(s,
				key,
				index,
				numThreads,
				InputIndexable[index],
			)
		}(i)
	}

	wg.Wait()

	// Assemble responses
	c.AssembleCDQueryThreadResults(s, input, numThreads, result)
	// Results are 2-D array, where there are |encoded file size| x |file size| rows and columns
	// results := C.GoBytes(unsafe.Pointer(*result),C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	finalResponse := make([][]byte, c.GetNUM_CD_KEYS())

	for i := 0; i < c.GetNUM_CD_KEYS(); i++ {
		finalResponse[i] = C.GoBytes(unsafe.Pointer(resultIndexable[i]), C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	}

	// Add artificial delay
	elapsed := time.Now().Sub(start)
	time.Sleep(time.Duration(delay) * time.Second)

	C.free(unsafe.Pointer(key))
	resp := common.CD732SearchResponse{
		Results:       finalResponse,
		ServerLatency: elapsed,
		ReceiveTime:   receive,
	}

	c.FreeServer(s)
	send := time.Now()
	resp.SendTime = send
	return resp, nil
}