// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// geth is the official command-line client for Ethereum.
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/console/prompt"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"

	// Force-load the tracer engines to trigger registration
	_ "github.com/ethereum/go-ethereum/eth/tracers/js"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"

	"github.com/urfave/cli/v2"
)

const (
	clientIdentifier = "geth" // Client identifier to advertise over the network
)

var (
	// flags that configure the node
	nodeFlags = flags.Merge([]cli.Flag{ // Node에 관한 Flag
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.MinFreeDiskSpaceFlag,
		utils.KeyStoreDirFlag,
		utils.ExternalSignerFlag,
		utils.NoUSBFlag,
		utils.USBFlag,
		utils.SmartCardDaemonPathFlag,
		utils.OverrideCancun,
		utils.EnablePersonal,
		utils.TxPoolLocalsFlag,
		utils.TxPoolNoLocalsFlag,
		utils.TxPoolJournalFlag,
		utils.TxPoolRejournalFlag,
		utils.TxPoolPriceLimitFlag,
		utils.TxPoolPriceBumpFlag,
		utils.TxPoolAccountSlotsFlag,
		utils.TxPoolGlobalSlotsFlag,
		utils.TxPoolAccountQueueFlag,
		utils.TxPoolGlobalQueueFlag,
		utils.TxPoolLifetimeFlag,
		utils.SyncModeFlag,
		utils.SyncTargetFlag,
		utils.ExitWhenSyncedFlag,
		utils.GCModeFlag,
		utils.SnapshotFlag,
		utils.TxLookupLimitFlag,
		utils.LightServeFlag,
		utils.LightIngressFlag,
		utils.LightEgressFlag,
		utils.LightMaxPeersFlag,
		utils.LightNoPruneFlag,
		utils.LightKDFFlag,
		utils.UltraLightServersFlag,
		utils.UltraLightFractionFlag,
		utils.UltraLightOnlyAnnounceFlag,
		utils.LightNoSyncServeFlag,
		utils.EthRequiredBlocksFlag,
		utils.LegacyWhitelistFlag,
		utils.BloomFilterSizeFlag,
		utils.CacheFlag,
		utils.CacheDatabaseFlag,
		utils.CacheTrieFlag,
		utils.CacheTrieJournalFlag,
		utils.CacheTrieRejournalFlag,
		utils.CacheGCFlag,
		utils.CacheSnapshotFlag,
		utils.CacheNoPrefetchFlag,
		utils.CachePreimagesFlag,
		utils.CacheLogSizeFlag,
		utils.FDLimitFlag,
		utils.CryptoKZGFlag,
		utils.ListenPortFlag,
		utils.DiscoveryPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.MiningEnabledFlag,
		utils.MinerGasLimitFlag,
		utils.MinerGasPriceFlag,
		utils.MinerEtherbaseFlag,
		utils.MinerExtraDataFlag,
		utils.MinerRecommitIntervalFlag,
		utils.MinerNewPayloadTimeout,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DNSDiscoveryFlag,
		utils.DeveloperFlag,
		utils.DeveloperPeriodFlag,
		utils.DeveloperGasLimitFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.EthStatsURLFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.GpoMaxGasPriceFlag,
		utils.GpoIgnoreGasPriceFlag,
		configFileFlag,
	}, utils.NetworkFlags, utils.DatabasePathFlags)

	rpcFlags = []cli.Flag{ // RPC에 대한 flag
		utils.HTTPEnabledFlag,
		utils.HTTPListenAddrFlag,
		utils.HTTPPortFlag,
		utils.HTTPCORSDomainFlag,
		utils.AuthListenFlag,
		utils.AuthPortFlag,
		utils.AuthVirtualHostsFlag,
		utils.JWTSecretFlag,
		utils.HTTPVirtualHostsFlag,
		utils.GraphQLEnabledFlag, // graphQL 쓰네
		utils.GraphQLCORSDomainFlag,
		utils.GraphQLVirtualHostsFlag,
		utils.HTTPApiFlag,
		utils.HTTPPathPrefixFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.WSPathPrefixFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
		utils.InsecureUnlockAllowedFlag,
		utils.RPCGlobalGasCapFlag,
		utils.RPCGlobalEVMTimeoutFlag,
		utils.RPCGlobalTxFeeCapFlag,
		utils.AllowUnprotectedTxs,
	}

	metricsFlags = []cli.Flag{ // DB관련 매트릭
		utils.MetricsEnabledFlag,
		utils.MetricsEnabledExpensiveFlag,
		utils.MetricsHTTPFlag,
		utils.MetricsPortFlag,
		utils.MetricsEnableInfluxDBFlag,
		utils.MetricsInfluxDBEndpointFlag,
		utils.MetricsInfluxDBDatabaseFlag,
		utils.MetricsInfluxDBUsernameFlag,
		utils.MetricsInfluxDBPasswordFlag,
		utils.MetricsInfluxDBTagsFlag,
		utils.MetricsEnableInfluxDBV2Flag,
		utils.MetricsInfluxDBTokenFlag,
		utils.MetricsInfluxDBBucketFlag,
		utils.MetricsInfluxDBOrganizationFlag,
	}
)

var app = flags.NewApp("the go-ethereum command line interface")

func init() {
	// Initialize the CLI app and start Geth
	app.Action = geth
	app.Copyright = "Copyright 2013-2023 The go-ethereum Authors"
	app.Commands = []*cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		importPreimagesCommand,
		exportPreimagesCommand,
		removedbCommand,
		dumpCommand,
		dumpGenesisCommand,
		// See accountcmd.go:
		accountCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		versionCommand,
		versionCheckCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
		// see dbcmd.go
		dbCommand,
		// See cmd/utils/flags_legacy.go
		utils.ShowDeprecated,
		// See snapshot.go
		snapshotCommand,
		// See verkle.go
		verkleCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = flags.Merge(
		nodeFlags,
		rpcFlags,
		consoleFlags,
		debug.Flags,
		metricsFlags,
	)

	app.Before = func(ctx *cli.Context) error { // command 실행 전
		flags.MigrateGlobalFlags(ctx) // 전역 플래그
		return debug.Setup(ctx)       // 디버깅 셋
	}
	app.After = func(ctx *cli.Context) error { // command 실행 후
		debug.Exit()         // 디버깅 종료
		prompt.Stdin.Close() // Resets terminal mode. 터미널 모드를 변경했으므로 다시 닫고 원래 상태
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// prepare manipulates memory cache allowance and setups metric system.
// This function should be called before launching devp2p stack.
func prepare(ctx *cli.Context) { // 메모리 캐시와 시스템 메트릭
	// If we're running a known preset, log it for convenience.
	switch { // 테스트넷
	case ctx.IsSet(utils.RinkebyFlag.Name):
		log.Info("Starting Geth on Rinkeby testnet...")

	case ctx.IsSet(utils.GoerliFlag.Name):
		log.Info("Starting Geth on Görli testnet...")

	case ctx.IsSet(utils.SepoliaFlag.Name):
		log.Info("Starting Geth on Sepolia testnet...")

	case ctx.IsSet(utils.DeveloperFlag.Name): // dev 모드는 뭐지? 로컬인가?
		log.Info("Starting Geth in ephemeral dev mode...")
		log.Warn(`You are running Geth in --dev mode. Please note the following:

  1. This mode is only intended for fast, iterative development without assumptions on
     security or persistence.
  2. The database is created in memory unless specified otherwise. Therefore, shutting down
     your computer or losing power will wipe your entire block data and chain state for
     your dev environment.
  3. A random, pre-allocated developer account will be available and unlocked as
     eth.coinbase, which can be used for testing. The random dev account is temporary,
     stored on a ramdisk, and will be lost if your machine is restarted.
  4. Mining is enabled by default. However, the client will only seal blocks if transactions
     are pending in the mempool. The miner's minimum accepted gas price is 1.
  5. Networking is disabled; there is no listen-address, the maximum number of peers is set
     to 0, and discovery is disabled.
`)

	case !ctx.IsSet(utils.NetworkIdFlag.Name):
		log.Info("Starting Geth on Ethereum mainnet...") // 아무 옵션 없으면 메인넷 고
	}
	// If we're a full node on mainnet without --cache specified, bump default cache allowance
	// 싱크 모드가 라이트가 아님 즉 풀노드 모드
	// 싱크 모드별 다루는 데이터 사이즈가 다르므로 캐시 크기 세팅 다르게... 최적화
	if ctx.String(utils.SyncModeFlag.Name) != "light" && !ctx.IsSet(utils.CacheFlag.Name) && !ctx.IsSet(utils.NetworkIdFlag.Name) {
		// Make sure we're not on any supported preconfigured testnet either
		if !ctx.IsSet(utils.SepoliaFlag.Name) &&
			!ctx.IsSet(utils.RinkebyFlag.Name) &&
			!ctx.IsSet(utils.GoerliFlag.Name) &&
			!ctx.IsSet(utils.DeveloperFlag.Name) {
			// Nope, we're really on mainnet. Bump that cache up!
			log.Info("Bumping default cache on mainnet", "provided", ctx.Int(utils.CacheFlag.Name), "updated", 4096)
			ctx.Set(utils.CacheFlag.Name, strconv.Itoa(4096)) // 캐시 크기 4096 (byte인가?)
		}
	}
	// If we're running a light client on any network, drop the cache to some meaningfully low amount
	if ctx.String(utils.SyncModeFlag.Name) == "light" && !ctx.IsSet(utils.CacheFlag.Name) {
		log.Info("Dropping default light client cache", "provided", ctx.Int(utils.CacheFlag.Name), "updated", 128)
		ctx.Set(utils.CacheFlag.Name, strconv.Itoa(128)) // 캐시크기 128
	}

	// Start metrics export if enabled
	// 모니터링에 수집할 매트릭
	utils.SetupMetrics(ctx)

	// Start system runtime metrics collection
	// 3초마다 메트릭 수집
	go metrics.CollectProcessMetrics(3 * time.Second)
}

// geth is the main entry point into the system if no special subcommand is run.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
// 터미널에서 geth 명령어 입력 시 호출
func geth(ctx *cli.Context) error {
	if args := ctx.Args().Slice(); len(args) > 0 { // 인수 체크
		return fmt.Errorf("invalid command: %q", args[0]) // 있으면 에러 생성 후, 반환
	}

	prepare(ctx)                        // 실행 준비(시스템 캐시와 매트릭 셋)
	stack, backend := makeFullNode(ctx) // TODO 풀노드 생성 추가 파악 필요
	defer stack.Close()                 // geth 함수 return시 stack close

	startNode(ctx, stack, backend, false) // 노드 시작
	stack.Wait()                          // 노드 종료까지 대기
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node, backend ethapi.Backend, isConsole bool) {
	debug.Memsize.Add("node", stack) // 디버그 메모리 사이즈

	// Start up the node itself
	utils.StartNode(ctx, stack, isConsole) // 노드 시작(콘솔여부?)

	// Unlock any account specifically requested
	unlockAccounts(ctx, stack) // 특정 계정 잠금 해제(개인키 활성화..밑에 코드 있으니 자세한건 아래에..)

	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16) // 이벤트 채널 생성
	stack.AccountManager().Subscribe(events)      // TODO 이벤트 변화 관찰 같은건가?

	// Create a client to interact with local geth node.
	rpcClient, err := stack.Attach() // RPC클라이언트 생성
	if err != nil {
		utils.Fatalf("Failed to attach to self: %v", err)
	}
	ethClient := ethclient.NewClient(rpcClient)

	go func() { // go 루틴 시작
		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() { // 지갑 계속 체크
			if err := wallet.Open(""); err != nil { // TODO 지갑을 연다는게 무슨 뜻?
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived: // 지갑 도착
				if err := event.Wallet.Open(""); err != nil { // TODO 지갑 열어
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened: // 지갑 이미 열림
				status, _ := event.Wallet.Status() // 지갑 상태 저장, _ 반환 에러 무시
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				var derivationPaths []accounts.DerivationPath // HD wallet 말하는 거(e.g., m/44'/60'/0'/0/0)
				if event.Wallet.URL().Scheme == "ledger" {    // ledger에서 가져온 지갑?
					derivationPaths = append(derivationPaths, accounts.LegacyLedgerBaseDerivationPath) // ledger derivation path는 좀 고유한 듯?
				}
				derivationPaths = append(derivationPaths, accounts.DefaultBaseDerivationPath) // default path 붙이기

				event.Wallet.SelfDerive(derivationPaths, ethClient) // TODO derivation path 따라 키 생성
				//m / purpose' / coin_type' / account' / change / address_index

			case accounts.WalletDropped: // 지갑 끊김
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// Spawn a standalone goroutine for status synchronization monitoring,
	// close the node when synchronization is complete if user required.
	if ctx.Bool(utils.ExitWhenSyncedFlag.Name) { // 동기화 완료되면 노드 종료 여부 설정 확인
		go func() { // 설정 했음
			sub := stack.EventMux().Subscribe(downloader.DoneEvent{}) // EventMux로 DoneEvent(동기화 완료 이벤트) subscribe.
			defer sub.Unsubscribe()                                   // surrounding function 종료 시, unsubscribe
			for {                                                     // 무한 반복
				event := <-sub.Chan() // subscribe한 event channel에서 이벤트 대기
				if event == nil {     // 이벤트 없음
					continue
				}
				done, ok := event.Data.(downloader.DoneEvent) // 이벤트 있고 downloader.DoneEvent 확인
				if !ok {                                      //// 타입 변환 실패
					continue
				}
				if timestamp := time.Unix(int64(done.Latest.Time), 0); time.Since(timestamp) < 10*time.Minute { // TODO 왜 10분? 동기화 완료 후 10분 동안 무언가를 해야하나? 동기화 완료 시점이 10분 이내인 경우?
					log.Info("Synchronisation completed", "latestnum", done.Latest.Number, "latesthash", done.Latest.Hash(),
						"age", common.PrettyAge(timestamp)) // 동기화 완료 로그 메시지
					stack.Close() // 노드 종료
				}
			}
		}()
	}

	// Start auxiliary services if enabled
	if ctx.Bool(utils.MiningEnabledFlag.Name) || ctx.Bool(utils.DeveloperFlag.Name) { // 마이닝 혹은 개발자 모드 여부
		// Mining only makes sense if a full Ethereum node is running
		if ctx.String(utils.SyncModeFlag.Name) == "light" { // 마이닝이고 라이드노드 노노
			utils.Fatalf("Light clients do not support mining")
		}
		ethBackend, ok := backend.(*eth.EthAPIBackend) // backend 인스턴스가 *eth.EthAPIBackend 타입인지?
		if !ok {
			utils.Fatalf("Ethereum service not running")
		}
		// Set the gas price to the limits from the CLI and start mining
		gasprice := flags.GlobalBig(ctx, utils.MinerGasPriceFlag.Name) // 가스 가격 로드
		ethBackend.TxPool().SetGasPrice(gasprice)                      // 마이닝에 사용할 가스 가격. 트랜잭션 풀에서 가스 가격 가져옴
		if err := ethBackend.StartMining(); err != nil {               // 마이닝 시작 에러
			utils.Fatalf("Failed to start mining: %v", err)
		}
	}
}

// unlockAccounts unlocks any account specifically requested.
func unlockAccounts(ctx *cli.Context, stack *node.Node) {
	var unlocks []string                                                     // 언락 계정 리스트
	inputs := strings.Split(ctx.String(utils.UnlockedAccountFlag.Name), ",") // 컨텍스트에서 UnlockedAccountFlag 이름 가져옴.
	for _, input := range inputs {
		if trimmed := strings.TrimSpace(input); trimmed != "" { // 트리밍
			unlocks = append(unlocks, trimmed) // 언락 목록 생성
		}
	}
	// Short circuit if there is no account to unlock.
	if len(unlocks) == 0 { // 언락할 계정 없음
		return
	}
	// If insecure account unlocking is not allowed if node's APIs are exposed to external.
	// Print warning log to user and skip unlocking.
	if !stack.Config().InsecureUnlockAllowed && stack.Config().ExtRPCEnabled() { // insecure unlock 허용 안됨. 외부 RPC로 활성화?
		utils.Fatalf("Account unlock with HTTP access is forbidden!")
	}
	backends := stack.AccountManager().Backends(keystore.KeyStoreType) // keyStore를 관리할 백엔드 가져옴.
	if len(backends) == 0 {                                            // 키스토어 관리 백엔드가 없음.
		log.Warn("Failed to unlock accounts, keystore is not available")
		return
	}
	ks := backends[0].(*keystore.KeyStore)   // 첫 번째 백엔드를 key store 타입으로
	passwords := utils.MakePasswordList(ctx) // 암호 목록 생성
	for i, account := range unlocks {        // 계정을 하나씩 언락
		unlockAccount(ks, account, i, passwords)
	}
}
