/* Copied file from https://github.com/ucbrise/dory/ */
package common

import "time"

const Test = "HELLOOOOOO"
const MAX_KEYWORD_SIZE = 32

type Server struct {
	Addr        string
	ID          string
	Port        string
	CertFile    string
	KeyFile     string
	IsByzantine bool
}

type SystemConfig struct {
	MasterAddr         string
	MasterID           string
	MasterPort         string
	MasterCertFile     string
	MasterKeyFile      string
	ClientAddrs        []string
	ClientIDs          []string
	Servers            []Server
	OutDir             string
	SSHKeyPath         string
	BaselineServerAddr string
	BaselineServerID   string
	BaselineClientAddr string
	BaselineClientID   string
}

type ServerConfig struct {
	Addr       string
	Port       string
	CertFile   string
	KeyFile    string
	OutDir     string
	PartyIndex int
}

type ClientConfig struct {
	Addr   []string
	Port   []string
	OutDir string
}

// configFile string,logNumFiles,fileSizeBytes,p,t,k,r,b,encodeAcross int
type SetupRequest struct {
	BenchmarkDir  string
	LogNumFiles   uint
	FileSizeBytes uint
	T             int
	K             int
	R             int
	B             int
	Rho           int
	Mode          int
	IsByzantine   int
	DelayTime     int
	NumThreads    int
	CheckMAC      int
}

type SetupResponse struct {
	ServerLatency time.Duration
}

type TreeSearchRequest struct {
	Key []byte
}

type TreeSearchResponse struct {
	Results       [][]byte
	PartyIndex    int
	ServerLatency time.Duration
	ReceiveTime   time.Time
	SendTime      time.Time
}

type ShamirSearchRequest struct {
	Key [][]byte
}

type ShamirSearchResponse struct {
	Results       [][]byte
	ServerLatency time.Duration
	ReceiveTime   time.Time
	SendTime      time.Time
}

type MultipartySearchRequest struct {
	Key []byte
}

type MultipartySearchResponse struct {
	Results       [][]byte
	ServerLatency time.Duration
	ReceiveTime   time.Time
	SendTime      time.Time
}

type HollantiSearchRequest struct {
	Key [][]byte
}

type HollantiSearchResponse struct {
	Results       [][]byte
	ServerLatency time.Duration
	ReceiveTime   time.Time
	SendTime      time.Time
}

type CD732SearchRequest struct {
	Key []byte
}

type CD732SearchResponse struct {
	Results       [][]byte
	ServerLatency time.Duration
	ReceiveTime   time.Time
	SendTime      time.Time
}

type WoodruffSearchRequest struct {
	Key []byte
}

type WoodruffSearchResponse struct {
	Results       [][]byte
	ServerLatency time.Duration
	ReceiveTime   time.Time
	SendTime      time.Time
}

type TestRequest struct {
	Msg string
}

type TestResponse struct {
	Msg string
}

const (
	SETUP_REQUEST uint8 = iota
	TREE_SEARCH_REQUEST
	SHAMIR_SEARCH_REQUEST
	MULTIPARTY_SEARCH_REQUEST
	HOLLANTI_SEARCH_REQUEST
	CD732_SEARCH_REQUEST
	WOODRUFF_SEARCH_REQUEST
	TEST_REQUEST
)
