#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace mapr {

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = 0);
    ~ThreadPool();

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    // Submit a task returning void
    template<typename F>
    void submit(F&& f) {
        submit_impl(std::forward<F>(f), nullptr);
    }

    // Submit a task returning a value
    template<typename F>
    auto submit_future(F&& f) -> std::future<decltype(f())> {
        using Result = decltype(f());
        auto task = std::make_shared<std::packaged_task<Result()>>(std::forward<F>(f));
        std::future<Result> fut = task->get_future();
        submit_impl([task]() { (*task)(); }, nullptr);
        return fut;
    }

    // Submit with explicit index (for work-stealing)
    template<typename F>
    void submit_indexed(size_t worker_index, F&& f) {
        submit_impl(std::forward<F>(f), &worker_index);
    }

    // Wait for all pending tasks to complete
    void wait_idle();

    // Get number of worker threads
    size_t size() const { return workers_.size(); }

    // Get queue depth (approximate)
    size_t pending_count() const;

private:
    struct Task {
        std::function<void()> func;
        size_t preferred_worker = SIZE_MAX; // SIZE_MAX = any worker
    };

    void submit_impl(std::function<void()>&& func, const size_t* preferred_worker);
    void worker_loop(size_t index);

    std::vector<std::thread> workers_;
    std::vector<std::queue<Task>> local_queues_;
    std::queue<Task> global_queue_;
    mutable std::mutex global_mutex_;
    std::condition_variable global_cv_;
    std::atomic<bool> shutdown_{false};
    std::atomic<size_t> active_tasks_{0};
    std::condition_variable idle_cv_;
    mutable std::mutex idle_mutex_;
};

} // namespace mapr