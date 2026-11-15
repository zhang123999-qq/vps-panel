package api

import (
	"sync"
	"sync/atomic"
	"testing"
)

// 并发审计：同一 (server, port) 的 try-lock 必须有且只有一个赢家，
// 否则会出现两个部署/测速同时写同一份远端配置。
func TestTryLockPlanSingleWinner(t *testing.T) {
	s := &Server{}
	var wg sync.WaitGroup
	var winners int32

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.tryLockPlan(1, 443); ok {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("应有且只有 1 个赢家，实际 %d", winners)
	}

	// 不同端口互不影响
	if _, ok := s.tryLockPlan(1, 444); !ok {
		t.Fatal("不同端口不应被阻塞")
	}
	// 不同服务器互不影响
	if _, ok := s.tryLockPlan(2, 443); !ok {
		t.Fatal("不同服务器不应被阻塞")
	}
}

// lockPlan 是阻塞锁：并发 N 个写入同一键时必须串行（用计数器验证临界区不重叠）
func TestLockPlanSerializes(t *testing.T) {
	s := &Server{}
	var inside int32
	var maxInside int32
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := s.lockPlan(7, 8443)
			defer unlock()
			cur := atomic.AddInt32(&inside, 1)
			mu.Lock()
			if cur > maxInside {
				maxInside = cur
			}
			mu.Unlock()
			atomic.AddInt32(&inside, -1)
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("临界区发生了重叠，最大并发 %d", maxInside)
	}
}
