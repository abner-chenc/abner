package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"sync"
	"time"
)

const chan_nums int = 2000000

func Create_threads() {
	log.Println("Create thread")

	add := func(w *sync.WaitGroup, strs []int) {
		strs[0] = 1
		i := 0
		i++
		w.Done()
	}

	t1 := time.Now()
	for {
		var wg sync.WaitGroup
		for i := 0; i < chan_nums; i++ {
			strs := make([]int, 10)
			wg.Add(1)
			go add(&wg, strs)
		}
		wg.Wait()

		time.Sleep(time.Millisecond * 5)
		t2 := time.Now()

		if t2.Sub(t1).Seconds() > 10 {
			log.Println(" thread is running...")
			t1 = t2
		}
	}
}

func main() {
	go Create_threads()
	log.Fatal(http.ListenAndServe("0.0.0.0:6365", nil))
}
