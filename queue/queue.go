package queue

import "sync"

type node struct {
	data interface{}
	next *node
}

type Queue struct {
	head    *node
	tail    *node
	count   int
	maxSize int
	lock    *sync.Mutex
}

// size <= 0 mean infinite
func NewQueue(size int, syn bool) *Queue {
	q := &Queue{maxSize: size}
	if syn {
		q.lock = &sync.Mutex{}
	}
	return q
}

func (q *Queue) Len() int {
	if q.lock != nil {
		q.lock.Lock()
		defer q.lock.Unlock()
	}

	return q.count
}

func (q *Queue) Push(item interface{}) (data interface{}) {
	if q.lock != nil {
		q.lock.Lock()
		defer q.lock.Unlock()
	}

	if q.maxSize > 0 && q.count == q.maxSize {
		// internal Poll
		n := q.head
		q.head = n.next

		if q.head == nil {
			q.tail = nil
		}
		q.count--
		data = n.data
	}

	n := &node{data: item}

	if q.tail == nil {
		q.tail = n
		q.head = n
	} else {
		q.tail.next = n
		q.tail = n
	}
	q.count++

	return
}

func (q *Queue) Poll() interface{} {
	if q.lock != nil {
		q.lock.Lock()
		defer q.lock.Unlock()
	}

	if q.head == nil {
		return nil
	}

	n := q.head
	q.head = n.next

	if q.head == nil {
		q.tail = nil
	}
	q.count--

	return n.data
}
