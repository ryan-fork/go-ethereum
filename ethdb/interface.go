// Copyright 2014 The go-ethereum Authors
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

//定义了数据库的接口
package ethdb

// Code using batches should try to add this much data to the batch.
// The value was determined empirically.
const IdealBatchSize = 100 * 1024

// Putter wraps the database write operation supported by both batches and regular databases.
//Putter接口定义了批量操作和普通操作的写入接口
type Putter interface {
	Put(key []byte, value []byte) error
}

// Database wraps all database operations. All methods are safe for concurrent use.
//数据库接口定义了所有的数据库操作， 所有的方法都是多线程安全的。
type Database interface {
	Putter
	Get(key []byte) ([]byte, error)
	Has(key []byte) (bool, error)
	Delete(key []byte) error
	Close()
	NewBatch() Batch
}

// Batch is a write-only database that commits changes to its host database
// when Write is called. Batch cannot be used concurrently.
//批量操作接口，不能多线程同时使用，当Write方法被调用的时候，数据库会提交写入的更改。
type Batch interface {
	Putter
	ValueSize() int // amount of data in the batch
	Write() error
	// Reset resets the batch for reuse
	Reset()
}
