#include "unit_test.hpp"
#include "utils.hpp"

#include <mutex>

#ifndef _WIN32
extern "C"
{
#include <arpa/inet.h>
}
#endif

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("JobQueue - One extra queue", "[jobqueue]")
    {
        SECTION("Extra queue jobs go away, others do not.")
        {
            Loop loop;
            JobQueue jq{loop};

            callback_waiter queued{[]() {}};
            callback_waiter good{[]() {}};
            callback_waiter bad{[]() {}};
            callback_waiter main_ok{[]() {}};

            // queue 3 jobs:
            //
            // one should run then queue a job onto the main job queue, which
            // should later execute without issue
            //
            // the next should destroy the created job queue
            //
            // the third should not execute
            loop.call([&]() {
                jq.call_soon([&]() { good.call(); });

                jq.call_soon([&]() { jq.stop(); });

                jq.call_soon([&]() { bad.call(); });

                // call_soon so it gets queued, as it is being called from inside the loop.
                loop.call_soon([&]() { main_ok.call(); });

                queued.call();
            });

            REQUIRE(queued.wait(10ms));

            REQUIRE(good.wait(10ms));
            REQUIRE_FALSE(bad.wait(10ms));
            REQUIRE(main_ok.wait(10ms));
        }

        SECTION("Tickers stop when their JobQueue dies")
        {
            Loop loop;
            JobQueue jq{loop};

            callback_waiter queued{[]() {}};

            std::atomic<int> bad_count = 0;
            std::atomic<int> good_count = 0;
            std::shared_ptr<Ticker> bad;
            std::shared_ptr<Ticker> good;

            // increment each counter every interval
            loop.call([&]() {
                bad = jq.call_every(1ms, [&]() { bad_count++; });
                good = loop.call_every(1ms, [&]() { good_count++; });

                loop.call_later(20ms, [&]() {
                    // our ticker references must expire before the job queue does
                    bad.reset();

                    jq.stop();
                });

                queued.call();
            });

            REQUIRE(queued.wait(10ms));
            std::this_thread::sleep_for(40ms);

            // allows for a bit of stupid timing, should be sufficient
            REQUIRE(good_count > bad_count + 5);
        }
    }

}  // namespace oxen::quic::test
