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
	"bytes"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

// Vote represents a single vote that an authorized signer made to modify the								一个Vote对象表示一张记名投票
// list of authorizations.
type Vote struct {
	Signer    common.Address `json:"signer"`    // Authorized signer that cast this vote					投票人
	Block     uint64         `json:"block"`     // Block number the vote was cast in (expire old votes)		投票的块号（检测投票过期用）
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization		被投票人
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account	更改授权
}

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
//Tally结构体用来记录投票数据，即某个(被投票)地址总共被投了多少票，新认证状态是什么
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or kicking someone
	Votes     int  `json:"votes"`     // Number of votes until now wanting to pass the proposal					到目前为止希望通过提案的投票数
}

// Snapshot is the state of the authorization voting at a given point in time.
//管理所有认证地址的结构体
type Snapshot struct {
	config   *params.CliqueConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache        // Cache of recent block signatures to speed up ecrecover

	Number  uint64                      `json:"number"`  // Block number where the snapshot was created			快照创建的区块号
	Hash    common.Hash                 `json:"hash"`    // Block hash where the snapshot was created
	Signers map[common.Address]struct{} `json:"signers"` // Set of authorized signers at this moment			全部已认证地址集合
	Recents map[uint64]common.Address   `json:"recents"` // Set of recent signers for spam protections			记录最近担当过数字签名算法的signer的地址(区块号作为key)
	Votes   []*Vote                     `json:"votes"`   // List of votes cast in chronological order			按时间顺序投票的投票名单(计名投票)
	Tally   map[common.Address]Tally    `json:"tally"`   // Current vote tally to avoid recalculating			被投票地址的投票次数(不计名)
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
//使用指定的启动参数创建新快照。 这个
//方法没有初始化最近的签名者集，所以只能使用if
//创世块
func newSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signers []common.Address) *Snapshot {
	snap := &Snapshot{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
		Tally:    make(map[common.Address]Tally),
	}
	for _, signer := range signers {
		snap.Signers[signer] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("clique-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("clique-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:   s.config,
		sigcache: s.sigcache,
		Number:   s.Number,
		Hash:     s.Hash,
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
		Votes:    make([]*Vote, len(s.Votes)),
		Tally:    make(map[common.Address]Tally),
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	copy(cpy.Votes, s.Votes)

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
//返回是否有意义在中投出指定的投票 给定快照上下文（例如，不要尝试添加已经授权的签名者）。
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, signer := s.Signers[address]

	//wcc
	signers := s.signers()
	if len(signers) == 1 && signer && authorize == false { //不能将最后一个授权人中踢出(踢出就没法挖矿了,而且再也无法授权新节点)
		//	log.Warn("!!!!!!!!!!!!!! Can't kick the last guy out !!!!!!!!!!!!!!") //, "err", nil
		return false
	}
	//wcc end

	return (signer && !authorize) || (!signer && authorize)
}

// cast adds a new vote into the tally.										为不计名计票添加了一个新的投票
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful										确保投票有意义(被投地址如已授权,则不能投授权票;被投地址如未授权,则不能投踢人票))
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally							添加到不计名投票
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.					从不计名计票中移除了先前的投票
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to		通过应用给定的标头创建新的授权快照 原始的
// the original one.																						更新认证地址列表
//更新认证地址列表
//Header.Coinbase作为被投票地址，投票内容authorized可由Header.Nonce取值确定
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) { //				headers: 来自区块主链上按从旧到新顺序排列的一组区块
	// Allow passing in no headers for cleaner code												//允许传入无标题以获得更清晰的代码
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied												完整性检查可以应用标头
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 { //											严格衔接在Snapshot当前状态(成员Number，Hash)之后
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot									遍历标题并创建新快照
	snap := s.copy()

	for _, header := range headers {
		//wcc 经测试,无投票时,Coinbase值是 0x0000000000000000000000000000000000000000
		//log.Warn("apply ", "header.Coinbase", header.Coinbase)
		//wcc end

		// Remove any votes on checkpoint blocks													删除检查点块上的任何投票
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
		}
		// Delete the oldest signer from the recent list to allow it signing again		从最近的列表中删除最旧的签名者以允许它再次签名
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers							解析授权密钥并检查签名者
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Signers[signer]; !ok { //												如果signer地址是尚未认证的，则直接退出本次迭代
			return nil, errUnauthorized
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				return nil, errUnauthorized
			}
		}
		snap.Recents[number] = signer

		// Header authorized, discard any previous votes from the signer					授权的Header，丢弃签名者以前的任何投票
		for i, vote := range snap.Votes {
			if vote.Signer == signer && vote.Address == header.Coinbase {
				// Uncast the vote from the cached tally											从不计名投票中移除了先前的投票
				snap.uncast(vote.Address, vote.Authorize)

				// Uncast the vote from the chronological list									从时间顺序列表(计名投票列表)中取消投票
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...) //					巧妙的方法,将后面的元素直接拼接到当前位置,达到移除当前元素的效果
				break                                                    // 				only one vote allowed
			}
		}
		// Tally up the new vote from the signer													从签名者那里获得新的投票
		var authorize bool
		switch {
		case bytes.Equal(header.Nonce[:], nonceAuthVote):
			authorize = true
		case bytes.Equal(header.Nonce[:], nonceDropVote):
			authorize = false
		default:
			return nil, errInvalidVote
		}
		if snap.cast(header.Coinbase, authorize) { //											为不计名计票添加了一个新的投票
			snap.Votes = append(snap.Votes, &Vote{ //												为计名投票添加了一个新的投票
				Signer:    signer, //投票人
				Block:     number,
				Address:   header.Coinbase, //被投票人
				Authorize: authorize,
			})
		}
		// If the vote passed, update the list of signers										如果投票通过(过半数)，请更新签名者列表
		if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Signers)/2 {
			if tally.Authorize {
				snap.Signers[header.Coinbase] = struct{}{} //加入授权人列表
			} else {
				delete(snap.Signers, header.Coinbase) //踢出

				// Signer list shrunk, delete any leftover recent caches			//签名者列表缩小，删除任何剩余的最近缓存
				if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
					delete(snap.Recents, number-limit)
				}
				// Discard any previous votes the deauthorized signer cast
				// 被投票人被踢出,删除所有该被投票人的投出的票 (计名与不计名)
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Signer == header.Coinbase {
						// Uncast the vote from the cached tally	//删除不计名
						snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

						// Uncast the vote from the chronological list	//删除计名
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			// 投票已出结果,删除所有投向该被投票人的票 (计名与不计名)
			for i := 0; i < len(snap.Votes); i++ { //删除计名
				if snap.Votes[i].Address == header.Coinbase {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.Coinbase) //删除不计名
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.				签名者按升序检索授权签名者列表
func (s *Snapshot) signers() []common.Address {
	signers := make([]common.Address, 0, len(s.Signers))
	for signer := range s.Signers {
		signers = append(signers, signer)
	}
	//按升序
	for i := 0; i < len(signers); i++ {
		for j := i + 1; j < len(signers); j++ {
			if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
				signers[i], signers[j] = signers[j], signers[i]
			}
		}
	}
	return signers
}

// inturn returns if a signer at a given block height is in-turn or not.		返回 给定的地址是否是给定块的签名者
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	signers, offset := s.signers(), 0 //按升序轮流记账
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}

	//wcc
	//length := uint64(0)
	//return (number % length) == uint64(offset) //故意弄宕
	if len(signers) == 0 {
		log.Warn("!!!!!!!!!!!!!! no signer. len(signers)==0 !!!!!!!!!!!!!!") //, "err", nil
		return false
	}
	//wcc end

	return (number % uint64(len(signers))) == uint64(offset)
}
