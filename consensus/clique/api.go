// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package clique

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
type API struct {
	chain  consensus.ChainReader
	clique *Clique
}

// GetSnapshot retrieves the state snapshot at a given block.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
//检索给定块的状态快照。
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSigners retrieves the list of authorized signers at the specified block.
//检索指定块的授权签名者列表。
func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// GetSignersAtHash retrieves the state snapshot at a given block.
//检索给定块的状态快照。
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// Proposals returns the current proposals the node tries to uphold and vote on.
//返回节点试图维护并投票的当前提案。
func (api *API) Proposals() map[common.Address]bool {
	api.clique.lock.RLock()
	defer api.clique.lock.RUnlock()

	proposals := make(map[common.Address]bool)
	for address, auth := range api.clique.proposals {
		proposals[address] = auth
	}
	return proposals
}

// Propose injects a new authorization proposal that the signer will attempt to
// push through.
//建议注入签名者将尝试的新授权提议
// 推动通过。
func (api *API) Propose(address common.Address, auth bool) {
	api.clique.lock.Lock()
	defer api.clique.lock.Unlock()				//defer用于资源的释放，会在函数返回之前进行调用

	api.clique.proposals[address] = auth
}

// Discard drops a currently running proposal, stopping the signer from casting
// further votes (either for or against).
//丢弃当前正在运行的提议，停止签名者进行投射
//进一步投票（赞成或反对）。
func (api *API) Discard(address common.Address) {
	api.clique.lock.Lock()
	defer api.clique.lock.Unlock()

	delete(api.clique.proposals, address)
}
