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

func RunHollantiQuery(
	req common.HollantiSearchRequest,
	config      common.ServerConfig,
	s           c.Server,
	threads     int,
	isByzantine *int,
	delay       int,
	numThreads  int) (common.HollantiSearchResponse, error) {

	start := time.Now()
	receive := time.Now()
	var index int

	//Little bit hacky, but using sizeof(&req) for sizeof pointer
	//num_rounds * encoded file size bytes

	result := (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&req))))
	resultIndexable := unsafe.Slice(result, c.GetNUM_ROUNDS())

	for i := 0; i < c.GetNUM_ROUNDS(); i++ {
		resultIndexable[i] = (*byte)(C.malloc(C.size_t(c.GetENCODED_FILE_SIZE_BYTES())))
	}

	key := (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&index))))

	//before_key_allocation := time.Now()
	keyIndexable := unsafe.Slice(key, C.int(c.GetNUM_ROUNDS()))
	keyLength := c.GetNUM_FILES()

	for i := 0; i < c.GetNUM_ROUNDS(); i++ {
		keyIndexable[i] = (*byte)(C.malloc(C.size_t(keyLength)))
		defer C.free(unsafe.Pointer(keyIndexable[i]))
		copy(unsafe.Slice(keyIndexable[i], keyLength),
			req.Key[i])
	}

	// Allocate space for threading result array
	input := (***byte)(C.malloc(C.size_t(numThreads) * C.size_t(unsafe.Sizeof(&index))))
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

	slice := c.GetNUM_ENCODED_FILES() / numThreads

	var wg sync.WaitGroup
	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func(index int) {
			defer wg.Done()
			c.RunHollantiQueryThread(s,
				key,
				index,
				index*slice,
				(index+1)*slice,
				InputIndexable[index],
			)
		}(i)
	}

	wg.Wait()

	// Run query on files

	// Run on threaded version
	c.AssembleHollantiQueryThreadResults(s, input, numThreads, result)

	// Results are 2-D array, where there are |encoded file size| x |file size| rows and columns
	// results := C.GoBytes(unsafe.Pointer(*result),C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	finalResponse := make([][]byte, c.GetNUM_ROUNDS())

	for i := 0; i < c.GetNUM_ROUNDS(); i++ {
		finalResponse[i] = C.GoBytes(unsafe.Pointer(resultIndexable[i]), C.int(c.GetENCODED_FILE_SIZE_BYTES()))
	}

	elapsed := time.Now().Sub(start)

	time.Sleep(time.Duration(delay) * time.Second)

	C.free(unsafe.Pointer(key))
	resp := common.HollantiSearchResponse{
		Results:       finalResponse,
		ServerLatency: elapsed,
		ReceiveTime:   receive,
	}
	C.free(unsafe.Pointer(result))
	c.FreeServer(s)
	send := time.Now()

	resp.SendTime = send

	return resp, nil
}
