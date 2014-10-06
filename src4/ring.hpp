#ifndef RING_HPP
#define RING_HPP

#include <atomic>
#include <cstddef>

template<typename T> class ring {

private:
    T *buf;
    std::atomic<size_t> head;
    std::atomic<size_t> tail;
    const size_t ring_size;

    size_t next(size_t current) {
        return (current + 1) % ring_size;
    }
 
public:
 
    ring(const size_t rsize, const size_t bsize) : ring_size(rsize)
    {
        std::atomic_init(&head, 0);
        std::atomic_init(&tail, 0);
        buf = new T[ring_size];
    }
 
    virtual ~ring()
    {
        delete [] buf;
    }
 
    bool m_push(const T& object) {
        size_t tmp_head = head.load(std::memory_order_relaxed);
        size_t nextHead = next(tmp_head);
        if (nextHead == tail.load(std::memory_order_acquire)) {
            return false;
        }
        buf[tmp_head] = object;
        head.store(nextHead, std::memory_order_release);
 
        return true;
    }

 
    bool m_ pop(T& object) {
        size_t tmp_tail = tail.load(std::memory_order_relaxed);
        if (tail == head.load(std::memory_order_acquire)) {
            return false;
        }
 
        object = buf[tmp_tail];
        tail.store(next(tmp_tail), std::memory_order_release);
        return true;
    }

    bool cas_push(const T& object) {
    }

    bool cas_ pop(T& object) {
    }
};

#endif // RING_HPP
