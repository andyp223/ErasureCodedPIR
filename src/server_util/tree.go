package server_util

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"c"
	"common"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

func RunTreeQuery(
	req common.TreeSearchRequest,
	config common.ServerConfig,
	s c.Server,
	threads int,
	isByzantine *int,
	delay int,
	numThreads int) (common.TreeSearchResponse, error) {
	receive := time.Now()

	start := time.Now()

	//Little bit hacky, but using sizeof(&req) for sizeof pointer
	//num_rounds * encoded file size bytes

	//TODO: When correctness is verified, try passing empty pointers instead of malloced ones
	result := (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&req))))
	resultIndexable := unsafe.Slice(result, c.GetNUM_ROUNDS())
	defer C.free(unsafe.Pointer(result))

	for i := 0; i < c.GetNUM_ROUNDS(); i++ {
		resultIndexable[i] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
		defer C.free(unsafe.Pointer(resultIndexable[i]))
	}

	key := (*byte)(C.CBytes(req.Key))

	// Allocate space for threading result array
	input := (***byte)(C.malloc(C.size_t(numThreads) * C.size_t(unsafe.Sizeof(&key))))
	defer C.free(unsafe.Pointer(input))

	InputIndexable := unsafe.Slice(input, C.int(numThreads))

	for i := 0; i < numThreads; i++ {
		InputIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&key))))
		tmpIndexable := unsafe.Slice(InputIndexable[i], C.int(c.GetNUM_ROUNDS()))
		defer C.free(unsafe.Pointer(InputIndexable[i]))
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	var wg sync.WaitGroup
	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func(index int) {
			defer wg.Done()
			c.RunOptimizedDPFTreeQueryThread(s,
				key,
				index,
				numThreads,
				InputIndexable[index],
			)
		}(i)
	}
	wg.Wait()

	// Assemble responses
	c.AssemblDPFTreeQueryThreadResults(s, input, numThreads, result)

	// Read Results into byte array, so it can be sent back using coded
	resultsIndexable := unsafe.Slice(result, c.GetNUM_ROUNDS())
	finalResponse := make([][]byte, c.GetNUM_ROUNDS())

	for i := 0; i < c.GetNUM_ROUNDS(); i++ {
		finalResponse[i] = C.GoBytes(unsafe.Pointer(resultsIndexable[i]), C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	}

	// Add artificial delay
	elapsed := time.Now().Sub(start)
	time.Sleep(time.Duration(delay) * time.Second)

	resp := common.TreeSearchResponse{
		Results:       finalResponse,
		PartyIndex:    config.PartyIndex,
		ServerLatency: elapsed,
		ReceiveTime:   receive,
	}
	c.FreeServer(s)
	fmt.Printf("IN TREE QUERY %v \n\n", finalResponse)
	send := time.Now()
	resp.SendTime = send
	return resp, nil
}
