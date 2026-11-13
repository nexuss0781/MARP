#include "mapr/thread_pool.hpp"

#include <algorithm>
#include <random>

namespace mapr {

ThreadPool::ThreadPool(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 1;
    }

    local_queues_.resize(num_threads);

    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this, i]() { worker_loop(i); });
    }
}

ThreadPool::~ThreadPool() {
    shutdown_ = true;
    global_cv_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

void ThreadPool::submit_impl(std::function<void()>&& func, const size_t* preferred_worker) {
    Task task{std::move(func), preferred_worker ? *preferred_worker : SIZE_MAX};

    if (preferred_worker && *preferred_worker < local_queues_.size()) {
        local_queues_[*preferred_worker].push(std::move(task));
    } else {
        std::lock_guard<std::mutex> lock(global_mutex_);
        global_queue_.push(std::move(task));
    }

    active_tasks_++;
    global_cv_.notify_one();
}

void ThreadPool::worker_loop(size_t index) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, workers_.size() - 1);

    while (!shutdown_) {
        Task task;
        bool got_task = false;

        // 1. Check local queue first
        if (!local_queues_[index].empty()) {
            task = std::move(local_queues_[index].front());
            local_queues_[index].pop();
            got_task = true;
        }

        // 2. Check global queue if no local task
        if (!got_task) {
            std::unique_lock<std::mutex> lock(global_mutex_);
            global_cv_.wait(lock, [this] { return shutdown_ || !global_queue_.empty(); });
            if (shutdown_) break;

            if (!global_queue_.empty()) {
                task = std::move(global_queue_.front());
                global_queue_.pop();
                got_task = true;
            }
        }

        // 3. Work stealing: try to steal from other local queues if still no task
        if (!got_task && workers_.size() > 1) {
            size_t victim = dist(gen);
            if (victim != index && !local_queues_[victim].empty()) {
                std::lock_guard<std::mutex> lock(global_mutex_); // reuse global mutex for simplicity
                if (!local_queues_[victim].empty()) {
                    task = std::move(local_queues_[victim].front());
                    local_queues_[victim].pop();
                    got_task = true;
                }
            }
        }

        if (got_task && task.func) {
            task.func();
            size_t remaining = --active_tasks_;
            if (remaining == 0) {
                std::lock_guard<std::mutex> lock(idle_mutex_);
                idle_cv_.notify_all();
            }
        }
    }
}

void ThreadPool::wait_idle() {
    std::unique_lock<std::mutex> lock(idle_mutex_);
    idle_cv_.wait(lock, [this] { return active_tasks_ == 0; });
}

size_t ThreadPool::pending_count() const {
    std::lock_guard<std::mutex> lock(global_mutex_);
    size_t count = global_queue_.size();
    for (const auto& q : local_queues_) {
        count += q.size();
    }
    return count;
}

} // namespace mapr