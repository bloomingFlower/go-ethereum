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

// evm executes EVM code snippets.
package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/cmd/evm/internal/t8ntool"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/urfave/cli/v2"
)

var (
	DebugFlag = &cli.BoolFlag{ // ## 디버그 모드
		Name:  "debug",
		Usage: "output full trace logs",
	}
	MemProfileFlag = &cli.StringFlag{ // ## 메모리 정보 주르륵?
		Name:  "memprofile",
		Usage: "creates a memory profile at the given path",
	}
	CPUProfileFlag = &cli.StringFlag{ // ## CPU 정보 주르륵?
		Name:  "cpuprofile",
		Usage: "creates a CPU profile at the given path",
	}
	StatDumpFlag = &cli.BoolFlag{ // ## Stack, Heap 메모리 정보 주르륵?
		Name:  "statdump",
		Usage: "displays stack and heap memory information",
	}
	CodeFlag = &cli.StringFlag{ // ## 이건 뭘까?
		Name:  "code",
		Usage: "EVM code",
	}
	CodeFileFlag = &cli.StringFlag{ // ## 디버그를 위한 것일까? -가 들어간 코드를..? 음 모르겠음
		Name:  "codefile",
		Usage: "File containing EVM code. If '-' is specified, code is read from stdin ",
	}
	GasFlag = &cli.Uint64Flag{ // ## 가스 리밋 설정
		Name:  "gas",
		Usage: "gas limit for the evm",
		Value: 10000000000,
	}
	PriceFlag = &flags.BigFlag{ // ## 어떤 price set?
		Name:  "price",
		Usage: "price set for the evm",
		Value: new(big.Int),
	}
	ValueFlag = &flags.BigFlag{ // ## 어떤 value set?
		Name:  "value",
		Usage: "value set for the evm",
		Value: new(big.Int),
	}
	DumpFlag = &cli.BoolFlag{ // ## 실행 후의 state를 dump하는 것일까?
		Name:  "dump",
		Usage: "dumps the state after the run",
	}
	InputFlag = &cli.StringFlag{ // ## 어떤 input?
		Name:  "input",
		Usage: "input for the EVM",
	}
	InputFileFlag = &cli.StringFlag{ // 어떤 input file?
		Name:  "inputfile",
		Usage: "file containing input for the EVM",
	}
	VerbosityFlag = &cli.IntFlag{ // 로그 레벨
		Name:  "verbosity",
		Usage: "sets the verbosity level",
	}
	BenchFlag = &cli.BoolFlag{ // benchmark
		Name:  "bench",
		Usage: "benchmark the execution",
	}
	CreateFlag = &cli.BoolFlag{ // call 보단 create? 이게 뭘까?
		Name:  "create",
		Usage: "indicates the action should be create rather than call",
	}
	GenesisFlag = &cli.StringFlag{ // 제네시스에 대한 어떤 거?
		Name:  "prestate",
		Usage: "JSON file with prestate (genesis) config",
	}
	MachineFlag = &cli.BoolFlag{ // bytecode 같은건가
		Name:  "json",
		Usage: "output trace logs in machine readable format (json)",
	}
	SenderFlag = &cli.StringFlag{ // sender 보여주기?
		Name:  "sender",
		Usage: "The transaction origin",
	}
	ReceiverFlag = &cli.StringFlag{ // reciver 보여주기?
		Name:  "receiver",
		Usage: "The transaction receiver (execution context)",
	}
	DisableMemoryFlag = &cli.BoolFlag{ // 메모리(힙?) 관련 출력 안함
		Name:  "nomemory",
		Value: true,
		Usage: "disable memory output",
	}
	DisableStackFlag = &cli.BoolFlag{ // 스택 관련 출력 안함
		Name:  "nostack",
		Usage: "disable stack output",
	}
	DisableStorageFlag = &cli.BoolFlag{ // 스토리지 관련 출력 안함
		Name:  "nostorage",
		Usage: "disable storage output",
	}
	DisableReturnDataFlag = &cli.BoolFlag{ // 리턴 데이터 출력 활성화
		Name:  "noreturndata",
		Value: true,
		Usage: "enable return data output",
	}
)

var stateTransitionCommand = &cli.Command{ // 상태 변경 명령어
	Name:    "transition",
	Aliases: []string{"t8n"}, // t8n? 이건 무슨 뜻?
	Usage:   "executes a full state transition",
	Action:  t8ntool.Transition,
	Flags: []cli.Flag{
		t8ntool.TraceFlag,
		t8ntool.TraceDisableMemoryFlag,
		t8ntool.TraceEnableMemoryFlag,
		t8ntool.TraceDisableStackFlag,
		t8ntool.TraceDisableReturnDataFlag,
		t8ntool.TraceEnableReturnDataFlag,
		t8ntool.OutputBasedir,
		t8ntool.OutputAllocFlag,
		t8ntool.OutputResultFlag,
		t8ntool.OutputBodyFlag,
		t8ntool.InputAllocFlag,
		t8ntool.InputEnvFlag,
		t8ntool.InputTxsFlag,
		t8ntool.ForknameFlag,
		t8ntool.ChainIDFlag,
		t8ntool.RewardFlag,
		t8ntool.VerbosityFlag,
	},
}

var transactionCommand = &cli.Command{ // 트랜잭션 명령어
	Name:    "transaction",
	Aliases: []string{"t9n"}, // 이건 t9n이네 t로 시작하는거 시퀀싱인가?
	Usage:   "performs transaction validation",
	Action:  t8ntool.Transaction,
	Flags: []cli.Flag{
		t8ntool.InputTxsFlag,
		t8ntool.ChainIDFlag,
		t8ntool.ForknameFlag,
		t8ntool.VerbosityFlag,
	},
}

var blockBuilderCommand = &cli.Command{
	Name:    "block-builder",
	Aliases: []string{"b11r"}, // 이건 b네 맞는 듯? 그런데 넘버링은? b와 r 사이에 11글자있다는거네. 이런 alias도 있구나
	Usage:   "builds a block",
	Action:  t8ntool.BuildBlock,
	Flags: []cli.Flag{
		t8ntool.OutputBasedir,
		t8ntool.OutputBlockFlag,
		t8ntool.InputHeaderFlag,
		t8ntool.InputOmmersFlag,
		t8ntool.InputWithdrawalsFlag,
		t8ntool.InputTxsRlpFlag,
		t8ntool.SealCliqueFlag,
		t8ntool.VerbosityFlag,
	},
}

var app = flags.NewApp("the evm command line interface") // geth 실행 단위?

func init() { // 초기화
	app.Flags = []cli.Flag{
		BenchFlag,
		CreateFlag,
		DebugFlag,
		VerbosityFlag,
		CodeFlag,
		CodeFileFlag,
		GasFlag,
		PriceFlag,
		ValueFlag,
		DumpFlag,
		InputFlag,
		InputFileFlag,
		MemProfileFlag,
		CPUProfileFlag,
		StatDumpFlag,
		GenesisFlag,
		MachineFlag,
		SenderFlag,
		ReceiverFlag,
		DisableMemoryFlag,
		DisableStackFlag,
		DisableStorageFlag,
		DisableReturnDataFlag,
	}
	app.Commands = []*cli.Command{
		compileCommand,
		disasmCommand,
		runCommand,
		blockTestCommand,
		stateTestCommand,
		stateTransitionCommand,
		transactionCommand,
		blockBuilderCommand,
	}
}

func main() {
	if err := app.Run(os.Args); err != nil { // cli argument를 받아 실행. 에러가 나면 아래 코드 실행
		code := 1                                       // 오류라서 1 리턴
		if ec, ok := err.(*t8ntool.NumberedError); ok { // assertion type 체크. error가 type이면 값은 ec에 ok는 true. 아니면 ok는 false
			code = ec.ExitCode() //
		}
		fmt.Fprintln(os.Stderr, err) // 에러 메시지 표준 에러 출력.
		os.Exit(code)                // 프로그램 종류
	}
}
