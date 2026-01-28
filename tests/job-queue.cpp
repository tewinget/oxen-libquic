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
        Loop loop;
        JobQueue jq{loop};

        SECTION("Extra queue jobs go away, others do not.")
        {
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

        SECTION("call_get exception if JobQueue goes away before fulfilled")
        {
            bool foo{false};

            jq.call([&]() {
                // this needs to happen after the call_get below is queued.  hopefully there
                // won't be some fruit-flavored platform where this sleep is insufficient.
                std::this_thread::sleep_for(10ms);
                jq.stop();
            });

            try
            {
                foo = jq.call_get([&]() { return true; });
            }
            catch (std::future_error& e)
            {
                // this is the expected case
            }

            REQUIRE_FALSE(foo);
        }
    }

}  // namespace oxen::quic::test
