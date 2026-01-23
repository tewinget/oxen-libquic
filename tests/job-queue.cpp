#include <mutex>

#include "unit_test.hpp"
#include "utils.hpp"

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
            auto jq = loop.make_job_queue();

            callback_waiter queued{[](){}};
            callback_waiter good{[](){}};
            callback_waiter bad{[](){}};
            callback_waiter main_ok{[](){}};

            // queue 3 jobs:
            //
            // one should run then queue a job onto the main job queue, which
            // should later execute without issue
            //
            // the next should destroy the created job queue
            //
            // the third should not execute
            loop.call([&](){
                    jq->call_soon([&]() {
                            good.call();
                            });

                    jq->call_soon([&]() {
                            jq.reset();
                            });

                    jq->call_soon([&]() {
                            bad.call();
                            });

                    // call_soon so it gets queued, as it is being called from inside the loop.
                    loop.call_soon([&](){
                            main_ok.call();
                            });

                    queued.call();
                    });

            REQUIRE(queued.wait(10ms));

            REQUIRE(good.wait(10ms));
            REQUIRE_FALSE(bad.wait(10ms));
            REQUIRE(main_ok.wait(10ms));
        }
    }

}  // namespace oxen::quic::test
