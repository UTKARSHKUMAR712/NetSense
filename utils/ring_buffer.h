#pragma once
// ============================================================
//  utils/ring_buffer.h — Lock-free-friendly ring buffer
//  Thread-safe with external lock, or single-threaded.
//  Never allocates beyond capacity. Oldest entries overwrite.
//  Reusable across NetSense+, WiFi Analyzer, Interceptor, etc.
// ============================================================
#include <array>
#include <cstddef>
#include <utility>

template<typename T, std::size_t Capacity>
class RingBuffer {
public:
    static_assert(Capacity > 0, "Capacity must be > 0");

    void push(T value) {
        _buf[_head] = std::move(value);
        _head = (_head + 1) % Capacity;
        if (_size < Capacity) ++_size;
        else _tail = (_tail + 1) % Capacity; // overwrite oldest
    }

    // Read oldest → newest
    template<typename Fn>
    void for_each(Fn&& fn) const {
        for (std::size_t i = 0; i < _size; ++i)
            fn(_buf[(_tail + i) % Capacity]);
    }

    void clear() { _head = _tail = _size = 0; }

    [[nodiscard]] std::size_t size()     const { return _size; }
    [[nodiscard]] bool        empty()    const { return _size == 0; }
    [[nodiscard]] bool        full()     const { return _size == Capacity; }
    [[nodiscard]] std::size_t capacity() const { return Capacity; }

    // Latest N items (clamped)
    const T& latest(std::size_t offset = 0) const {
        return _buf[(_head + Capacity - 1 - offset) % Capacity];
    }

private:
    std::array<T, Capacity> _buf{};
    std::size_t _head = 0;
    std::size_t _tail = 0;
    std::size_t _size = 0;
};
