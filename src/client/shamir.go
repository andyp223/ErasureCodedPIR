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
	"math"
	"time"
	"unsafe"
)

func ShamirQuery(index int) ([]byte, error) {

	start_time := time.Now()
	p := c.GetNUM_PARTIES()
	//q := c.Choose(p,c.GetT())

	pointer_size := C.size_t(unsafe.Sizeof(&index))
	keyLength := c.CalcShamirDPFKeyLength(c.GetLOG_NUM_ENCODED_FILES())

	//fmt.Printf("parties: %v \n log num encoded files %v \n num_rounds: %v \n",p,log_num_encoded,num_rounds)
	//Allocate Keys
	//uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
	//fmt.Println("Setting up keys")
	keys := (***byte)(C.malloc(C.size_t(p) * C.size_t(unsafe.Sizeof(&index))))
	defer C.free(unsafe.Pointer(keys))
	keysIndexable := unsafe.Slice(keys, C.int(p))

	for i := 0; i < p; i++ {
		keysIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * pointer_size))
		tmpIndexable := unsafe.Slice(keysIndexable[i], C.int(p))
		defer C.free(unsafe.Pointer(keysIndexable[i]))
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(keyLength)))
		}
	}

	// Generate Shamir Coefficients
	n := c.GetLOG_NUM_ENCODED_FILES()
	x := c.GetLOG_NUM_ENCODED_FILES() / 2

	if c.GetLOG_NUM_ENCODED_FILES()%2 != 0 {
		x += 1
	}

	y := n - x

	coeffs_x := (***byte)(C.malloc(C.size_t(C.size_t(c.GetNUM_ROUNDS()) * pointer_size)))
	coeffs_y := (***byte)(C.malloc(C.size_t(C.size_t(c.GetNUM_ROUNDS()) * pointer_size)))
	coeffs_xIndexable := unsafe.Slice(coeffs_x, c.GetNUM_ROUNDS())
	coeffs_yIndexable := unsafe.Slice(coeffs_y, c.GetNUM_ROUNDS())
	defer C.free(unsafe.Pointer(coeffs_x))
	defer C.free(unsafe.Pointer(coeffs_y))

	for i := 0; i < c.GetNUM_ROUNDS(); i++ {
		x_size := C.size_t(math.Pow(2, (float64)(x)))
		y_size := C.size_t(math.Pow(2, (float64)(y)))
		coeffs_xIndexable[i] = (**byte)(C.malloc(x_size * pointer_size))
		coeffs_yIndexable[i] = (**byte)(C.malloc(y_size * pointer_size))
		tmpIndexableX := unsafe.Slice(coeffs_xIndexable[i], x_size)
		tmpIndexableY := unsafe.Slice(coeffs_yIndexable[i], y_size)

		for j := 0; j < (int)(x_size); j++ {
			tmpIndexableX[j] = (*byte)(C.malloc(C.size_t(c.GetT() + c.GetNUM_ROUNDS())))
			C.memset(unsafe.Pointer(tmpIndexableX[j]), 0, C.size_t(c.GetT()+c.GetNUM_ROUNDS()))
		}

		for j := 0; j < (int)(y_size); j++ {
			tmpIndexableY[j] = (*byte)(C.malloc(C.size_t(c.GetT() + c.GetNUM_ROUNDS())))
			C.memset(unsafe.Pointer(tmpIndexableY[j]), 0, C.size_t(c.GetT()+c.GetNUM_ROUNDS()))
		}
	}
	//log.Printf("TOOK %v miliseconds to malloc \n",time.Now().Sub(before_malloc_time).Milliseconds());

	c.GenShamirCoeffs(n, c.GetT(), c.GetNUM_ROUNDS(), c.ConvertInt(index), coeffs_x, coeffs_y)

	c.GenOptShamirDPF(c.GetLOG_NUM_ENCODED_FILES(), c.ConvertInt(index), c.GetT(), c.GetNUM_PARTIES(), c.GetNUM_ROUNDS(), keys, coeffs_x, coeffs_y)

	//Get response length
	responseLength := c.CalcShamirResponseLength(c.GetLOG_NUM_ENCODED_FILES(), c.GetENCODED_FILE_SIZE_BYTES())
	//Allocate a responses vector
	responses := (***byte)(C.malloc(C.size_t(p) * pointer_size))
	defer C.free(unsafe.Pointer(responses))
	responsesIndexable := unsafe.Slice(responses, C.int(p))

	for i := 0; i < p; i++ {
		responsesIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * pointer_size))
		defer C.free(unsafe.Pointer(responsesIndexable[i]))
		tmpIndexable := unsafe.Slice(responsesIndexable[i], c.GetNUM_ROUNDS())
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(responseLength)))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	keys_time := time.Now()

	// Use Go Channels to manage which servers responded
	resps := make([]*common.ShamirSearchResponse, p)
	var serverLatency time.Duration
	res := make(chan int)
	count := 0
	errs := make([]error, p)
	var sendLatency time.Duration
	var receiveLatency time.Duration
	sendLatency = time.Microsecond
	receiveLatency = time.Microsecond
	//fmt.Printf("BEFORE REQUEST \n")
	//Send out requests
	for i := 0; i < int(p); i++ {
		var respError error
		resps[i] = &common.ShamirSearchResponse{}
		tmpIndexable := unsafe.Slice(keysIndexable[i], c.GetNUM_ROUNDS())
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
				common.SHAMIR_SEARCH_REQUEST,
				&common.ShamirSearchRequest{
					Key: serverKey,
				},
				resps[i],
				&respError,
			)
			r_time := time.Now()

			// if resps[i].ServerLatency > serverLatency {
			// 	serverLatency = resps[i].ServerLatency
			// }
			// //log.Printf(" s_time: %v resps[i].ReceiveTime %v\n", s_time,resps[i].ReceiveTime)
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

	// TODO: Find way to recieve all threads wihtout incurring overhead
	erasureIndexList := make([]byte, p)
	var returnedIndex int
	responded := 0

	for {
		returnedIndex = <-res
		responded += 1
		if errs[returnedIndex] == nil || errs[returnedIndex].Error() == "EOF" {
			//fmt.Printf("results %v %v",returnedIndex,resps[returnedIndex])
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

	serverLatency /= time.Duration((p - c.GetR()))
	receiveLatency /= time.Duration((p - c.GetR()))
	sendLatency /= time.Duration((p - c.GetR()))

	query_time := time.Now()

	//fmt.Printf("All responses received \n")
	testResponses := (***byte)(C.malloc(C.size_t(C.size_t(p-c.GetR()) * C.size_t((unsafe.Sizeof(&index))))))
	defer C.free(unsafe.Pointer(testResponses))
	testResponsesIndexable := unsafe.Slice(testResponses, C.int(p-c.GetR()))

	for i := 0; i < p-c.GetR(); i++ {
		testResponsesIndexable[i] = (**byte)(C.malloc(C.size_t(c.GetNUM_ROUNDS()) * C.size_t(unsafe.Sizeof(&index))))
		defer C.free(unsafe.Pointer(testResponsesIndexable[i]))
		tmpIndexable := unsafe.Slice(testResponsesIndexable[i], c.GetNUM_ROUNDS())
		for j := 0; j < c.GetNUM_ROUNDS(); j++ {
			tmpIndexable[j] = (*byte)(C.malloc(C.size_t(responseLength)))
			defer C.free(unsafe.Pointer(tmpIndexable[j]))
		}
	}

	curr := 0
	for i := 0; i < p; i++ {
		if erasureIndexList[i] != 0 {
			tmpIndexable1 := unsafe.Slice(testResponsesIndexable[curr], c.GetNUM_ROUNDS())
			for j := 0; j < c.GetNUM_ROUNDS(); j++ {
				//fmt.Printf("i:%v j:%v results:%v\n",i,j,resps[i].Results)
				copy(unsafe.Slice(tmpIndexable1[j], responseLength),
					resps[i].Results[j])

			}
			curr++
		}
	}

	finalResult := (*byte)(C.malloc(C.size_t(c.GetFILE_SIZE_BYTES())))
	var decode_time time.Time
	c.AssembleShamirResponses(client, (*byte)(C.CBytes(erasureIndexList)), testResponses, finalResult, coeffs_x, coeffs_y)
	decode_time = time.Now()

	LogFile.WriteString(genOutputString(2, serverDelayTime, numDelay, start_time, keys_time, query_time, decode_time, receiveLatency, serverLatency, sendLatency))

	defer C.free(unsafe.Pointer(finalResult))
	//C.memset(unsafe.Pointer(finalResult), 1, C.size_t(c.GetFILE_SIZE_BYTES()))

	// C.memset(unsafe.Pointer(finalResult), 1, C.size_t(c.GetFILE_SIZE_BYTES()))

	return C.GoBytes(unsafe.Pointer(finalResult), C.int(c.GetFILE_SIZE_BYTES())), nil

}