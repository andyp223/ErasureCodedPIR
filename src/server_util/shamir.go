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

func RunShamirQuery(
	req common.ShamirSearchRequest,
	config      common.ServerConfig,
	s           c.Server,
	threads     int,
	isByzantine *int,
	delay       int,
	numThreads  int) (common.ShamirSearchResponse, error) {
		start := time.Now()
		receive := time.Now()
		var index int
	
		//Little bit hacky, but using sizeof(&req) for sizeof pointer
		//num_rounds * encoded file size bytes
	
		//TODO: When correctness is verified, try passing empty pointers instead of malloced ones
		result := (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&req))))
		resultIndexable := unsafe.Slice(result, c.GetNUM_ROUNDS())
		defer C.free(unsafe.Pointer(result))
	
		resultLength := c.CalcShamirResponseLength(c.GetLOG_NUM_ENCODED_FILES(), c.GetENCODED_FILE_SIZE_BYTES())
	
		for i := 0; i < c.GetNUM_ROUNDS(); i++ {
			resultIndexable[i] = (*byte)(C.malloc(C.size_t(resultLength)))
			C.memset(unsafe.Pointer(resultIndexable[i]), 0, C.size_t(resultLength))
			defer C.free(unsafe.Pointer(resultIndexable[i]))
		}
	
		//fmt.Printf("resultLength: %v \n",resultLength)
	
		key := (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&index))))
		//defer C.free(unsafe.Pointer(key))
	
		keyIndexable := unsafe.Slice(key, C.int(c.GetNUM_ROUNDS()))
	
		// TODO: When correctnesss is verified, send via request
		keyLength := c.CalcShamirDPFKeyLength(c.GetLOG_NUM_ENCODED_FILES())
		//fmt.Printf("keylength: %v %v\n",c.GetLOG_NUM_ENCODED_FILES(),c.GetNUM_ROUNDS())
	
		defer C.free(unsafe.Pointer(key))
		for i := 0; i < c.GetNUM_ROUNDS(); i++ {
			keyIndexable[i] = (*byte)(C.malloc(C.size_t(keyLength)))
	
			copy(unsafe.Slice(keyIndexable[i], keyLength),
				req.Key[i])
		}
	
		// Allocate space for threading result array
		input := (***byte)(C.malloc(C.size_t(numThreads) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(input))
	
		InputIndexable := unsafe.Slice(input, C.int(numThreads))
	
		for i := 0; i < numThreads; i++ {
			InputIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&req))))
			tmpIndexable := unsafe.Slice(InputIndexable[i], C.int(c.GetNUM_ROUNDS()))
			defer C.free(unsafe.Pointer(InputIndexable[i]))
			for j := 0; j < c.GetNUM_ROUNDS(); j++ {
				tmpIndexable[j] = (*byte)(C.malloc(C.size_t(resultLength)))
				defer C.free(unsafe.Pointer(tmpIndexable[j]))
			}
		}
	
		// Run threads for query
		slice := c.GetNUM_ENCODED_FILES() / numThreads
		//fmt.Printf("Slice is: %v num encoded: %v \n",slice,c.GetNUM_ENCODED_FILES());
	
		var wg sync.WaitGroup
		wg.Add(numThreads)
		for i := 0; i < numThreads; i++ {
			go func(index int) {
				defer wg.Done()
				c.RunOptShamirDPFQueryThread(
					s,
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
		c.AssembleShamirQueryThreadResults(s, input, numThreads, result)
	
		finalResponse := make([][]byte, c.GetNUM_ROUNDS())
	
		for i := 0; i < c.GetNUM_ROUNDS(); i++ {
			finalResponse[i] = C.GoBytes(unsafe.Pointer(resultIndexable[i]), C.int(resultLength))
		}
	
		// SERVER LATENCY SHOULD NOT INCLUDE DELAY
		elapsed := time.Now().Sub(start)
	
		time.Sleep(time.Duration(delay) * time.Second)
	
		//fmt.Printf("SERVER_SIDE RESPONSE: %v \n",finalResponse)
		resp := common.ShamirSearchResponse{
			Results:       finalResponse,
			ServerLatency: elapsed,
			ReceiveTime:   receive,
		}
	
		c.FreeServer(s)
		send := time.Now()
	
		resp.SendTime = send
	
		return resp, nil
	}

